"""Concrete JavaScript-analysis modules + the ``build_js_modules`` factory.

Each module is a thin, dependency-free wrapper that applies the pure helpers in
:mod:`recon_platform.js_analysis.analyzers` (and the shared secret patterns from
:mod:`recon_platform.vision.detector`) to the script bodies the
:class:`~recon_platform.agents.js_analysis.JSAnalysisAgent` fetched, and returns
new assets/relations. Nothing here performs I/O — the agent already fetched the
text — so the family is safe to run offline and degrades to empty results when no
scripts were captured.

Endpoints and secrets reuse the existing ``ENDPOINT`` / ``SECRET`` asset types
(tagged ``attributes["via"]="js"``) so the Network / API-discovery agents and the
existing analysis rules pick them up unchanged; ``SOURCE_MAP`` is the one new
type. Every module captures errors into ``result.errors`` rather than raising.
"""

from __future__ import annotations

from recon_platform.core.config import Settings
from recon_platform.domain.enums import AssetType, RelationType
from recon_platform.domain.schemas import Asset, ReconResult, Relation
from recon_platform.js_analysis.analyzers import (
    extract_endpoints,
    extract_parameters,
    find_source_maps,
    is_internal_url,
)
from recon_platform.js_analysis.base import JSContext, JSModule
from recon_platform.vision.detector import find_secrets


def _js_file_key(url: str) -> str:
    return f"{AssetType.JS_FILE.value}:{url.lower()}"


class EndpointExtractionModule(JSModule):
    """Extract endpoint URLs / API paths and query parameters from scripts."""

    name = "js_endpoints"
    description = "Extract endpoints and request parameters from JavaScript bundles."

    async def run(self, ctx: JSContext) -> ReconResult:
        result = ReconResult(task_id="", module=self.name)
        endpoints: dict[str, Asset] = {}
        params: dict[str, Asset] = {}
        try:
            for url, body in ctx.sources.items():
                for ep in extract_endpoints(body, base_url=url):
                    ekey = f"{AssetType.ENDPOINT.value}:{ep.lower()}"
                    if ekey not in endpoints:
                        endpoints[ekey] = Asset(
                            type=AssetType.ENDPOINT,
                            value=ep,
                            source=self.name,
                            attributes={
                                "via": "js",
                                "js_file": url,
                                "internal": is_internal_url(ep, ctx.target),
                            },
                            confidence=0.7,
                        )
                        result.relations.append(
                            Relation(
                                source_key=_js_file_key(url),
                                target_key=ekey,
                                type=RelationType.REFERENCES,
                            )
                        )
                for p in extract_parameters(body, base_url=url):
                    pvalue = f"{p['name']} ({p['location']})"
                    pkey = f"{AssetType.API_PARAMETER.value}:{pvalue.lower()}"
                    if pkey not in params:
                        params[pkey] = Asset(
                            type=AssetType.API_PARAMETER,
                            value=pvalue,
                            source=self.name,
                            attributes={"name": p["name"], "location": p["location"], "via": "js"},
                            confidence=0.6,
                        )
            result.assets.extend(endpoints.values())
            result.assets.extend(params.values())
            if endpoints or params:
                result.notes.append(
                    f"Extracted {len(endpoints)} endpoint(s), {len(params)} parameter(s) from JS."
                )
        except Exception as exc:  # noqa: BLE001 - resilience contract
            result.errors.append(f"js endpoint extraction failed: {exc}")
        return result


class SecretDetectionModule(JSModule):
    """Detect high-signal secrets embedded in script bodies."""

    name = "js_secrets"
    description = "Detect API keys / tokens / private keys embedded in JavaScript."

    async def run(self, ctx: JSContext) -> ReconResult:
        result = ReconResult(task_id="", module=self.name)
        seen: set[str] = set()
        try:
            for url, body in ctx.sources.items():
                for kind, value in find_secrets(body):
                    skey = f"{AssetType.SECRET.value}:{value.lower()}"
                    if skey in seen:
                        continue
                    seen.add(skey)
                    secret = Asset(
                        type=AssetType.SECRET,
                        value=value,
                        source=self.name,
                        attributes={"via": "js", "kind": kind, "js_file": url},
                        confidence=0.85,
                    )
                    result.assets.append(secret)
                    result.relations.append(
                        Relation(
                            source_key=_js_file_key(url),
                            target_key=secret.key,
                            type=RelationType.CONTAINS,
                        )
                    )
            if seen:
                result.notes.append(f"Detected {len(seen)} secret(s) in JS.")
        except Exception as exc:  # noqa: BLE001 - resilience contract
            result.errors.append(f"js secret detection failed: {exc}")
        return result


class SourceMapDiscoveryModule(JSModule):
    """Discover source-map references that can reconstruct original source."""

    name = "js_source_maps"
    description = "Discover sourceMappingURL references exposing original source."

    async def run(self, ctx: JSContext) -> ReconResult:
        result = ReconResult(task_id="", module=self.name)
        seen: set[str] = set()
        try:
            for url, body in ctx.sources.items():
                for ref in find_source_maps(body, base_url=url):
                    mkey = f"{AssetType.SOURCE_MAP.value}:{ref.lower()}"
                    if mkey in seen:
                        continue
                    seen.add(mkey)
                    smap = Asset(
                        type=AssetType.SOURCE_MAP,
                        value=ref,
                        source=self.name,
                        attributes={"js_file": url},
                        confidence=0.8,
                    )
                    result.assets.append(smap)
                    result.relations.append(
                        Relation(
                            source_key=_js_file_key(url),
                            target_key=smap.key,
                            type=RelationType.REFERENCES,
                        )
                    )
            if seen:
                result.notes.append(f"Discovered {len(seen)} source map(s).")
        except Exception as exc:  # noqa: BLE001 - resilience contract
            result.errors.append(f"js source-map discovery failed: {exc}")
        return result


def build_js_modules(settings: Settings | None = None) -> list[JSModule]:
    """Return the enabled JS-analysis modules, honouring the per-capability toggles.

    With no settings (or all toggles on) the full set is returned. The modules are
    cheap, dependency-free objects, so construction is always safe.
    """
    js = settings.js_analysis if settings is not None else None
    modules: list[JSModule] = []
    if js is None or js.extract_endpoints:
        modules.append(EndpointExtractionModule())
    if js is None or js.extract_secrets:
        modules.append(SecretDetectionModule())
    if js is None or js.discover_source_maps:
        modules.append(SourceMapDiscoveryModule())
    return modules
