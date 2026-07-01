"""Concrete network-analysis modules + the ``build_network_modules`` factory.

Each module is a thin, dependency-free wrapper that applies the pure helpers in
:mod:`recon_platform.network.detectors` to the asset snapshot the
:class:`~recon_platform.agents.network.NetworkAgent` gathered from the knowledge
graph, and returns new network-layer assets/relations. Nothing here issues
network I/O — the modules only reason over what earlier agents already observed —
so the whole family is safe to run offline and degrades to empty results when the
graph holds nothing relevant.

Modules follow the same resilience contract as every other family: analysis
errors are captured in ``result.errors`` rather than raised, so one failing
module never aborts a run.

New asset types produced (all documented in :mod:`recon_platform.domain.enums`):

* ``JWT`` — a decoded (unverified) JSON Web Token, with any weaknesses in
  ``attributes["issues"]``.
* ``API_ENDPOINT`` — an endpoint characterized as ``graphql`` / ``rest`` traffic
  in ``attributes["api_type"]``.
* ``WEBSOCKET`` — a ``ws://`` / ``wss://`` endpoint (``attributes["secure"]``).

CORS hygiene attaches its findings to the existing ``HEADER`` asset it analyzed
(via an attribute merge into ``attributes["cors_issues"]``) rather than inventing
a new asset type, so the graph stays lean.
"""

from __future__ import annotations

from recon_platform.core.config import Settings
from recon_platform.domain.enums import AssetType, RelationType
from recon_platform.domain.schemas import Asset, ReconResult, Relation
from recon_platform.network.base import NetworkContext, NetworkModule
from recon_platform.network.detectors import (
    classify_api_endpoint,
    cors_issues,
    decode_jwt,
    find_jwts,
    websocket_endpoints,
)


def _cap(settings: Settings) -> int:
    """Per-module item budget (defensive against pathological inputs)."""
    return max(0, int(settings.network.max_items))


class JWTInspectionModule(NetworkModule):
    """Decode JWTs embedded in headers / tokens / endpoints and flag weaknesses.

    The signature is never verified — this is inspection, not validation. Each
    distinct token becomes one ``JWT`` asset; a ``REFERENCES`` relation links it
    back to the asset it was found in so the graph records provenance.
    """

    name = "jwt_inspection"
    description = "Decode JSON Web Tokens found in headers/tokens/URLs and flag weaknesses."

    async def run(self, ctx: NetworkContext) -> ReconResult:
        result = ReconResult(task_id="", module=self.name)
        cap = _cap(ctx.settings)
        # (asset, source_kind, text) tuples to scan, in priority order.
        sources: list[tuple[Asset, str, str]] = []
        for h in ctx.headers:
            sources.append((h, "header", str(h.attributes.get("value", h.value))))
        for t in ctx.tokens:
            sources.append((t, "token", t.value))
        for e in ctx.endpoints:
            sources.append((e, "url", e.value))

        seen: set[str] = set()
        try:
            for asset, kind, text in sources:
                if len(seen) >= cap:
                    break
                for raw in find_jwts(text):
                    decoded = decode_jwt(raw)
                    if decoded is None:
                        continue
                    key = f"jwt:{decoded.masked.lower()}"
                    jwt_asset = Asset(
                        type=AssetType.JWT,
                        value=decoded.masked,
                        source=self.name,
                        attributes={
                            "alg": decoded.alg,
                            "typ": decoded.typ,
                            "issues": decoded.issues,
                            "source_kind": kind,
                            "claims": sorted(str(k) for k in decoded.payload),
                        },
                        confidence=0.9,
                    )
                    result.assets.append(jwt_asset)
                    result.relations.append(
                        Relation(
                            source_key=asset.key,
                            target_key=jwt_asset.key,
                            type=RelationType.CONTAINS,
                        )
                    )
                    seen.add(key)
            if seen:
                result.notes.append(f"Decoded {len(seen)} JWT(s).")
        except Exception as exc:  # noqa: BLE001 - resilience contract
            result.errors.append(f"jwt inspection failed: {exc}")
        return result


class APIClassificationModule(NetworkModule):
    """Classify endpoints as GraphQL / REST traffic and flag introspection risk."""

    name = "api_classification"
    description = "Classify endpoints as GraphQL / REST traffic and flag introspection exposure."

    async def run(self, ctx: NetworkContext) -> ReconResult:
        result = ReconResult(task_id="", module=self.name)
        cap = _cap(ctx.settings)
        seen: set[str] = set()
        try:
            for e in ctx.endpoints:
                if len(seen) >= cap:
                    break
                api_type = classify_api_endpoint(e.value)
                if api_type is None:
                    continue
                key = f"{AssetType.API_ENDPOINT.value}:{e.value.lower()}"
                if key in seen:
                    continue
                seen.add(key)
                attrs: dict = {"api_type": api_type}
                if api_type == "graphql":
                    # A reachable GraphQL endpoint frequently allows schema
                    # introspection; flag it for manual confirmation.
                    attrs["introspection_risk"] = True
                api_asset = Asset(
                    type=AssetType.API_ENDPOINT,
                    value=e.value,
                    source=self.name,
                    attributes=attrs,
                    confidence=0.8,
                )
                result.assets.append(api_asset)
                result.relations.append(
                    Relation(
                        source_key=e.key,
                        target_key=api_asset.key,
                        type=RelationType.REFERENCES,
                    )
                )
            if seen:
                result.notes.append(f"Classified {len(seen)} API endpoint(s).")
        except Exception as exc:  # noqa: BLE001 - resilience contract
            result.errors.append(f"api classification failed: {exc}")
        return result


class WebSocketReviewModule(NetworkModule):
    """Surface ws:// / wss:// endpoints and flag unencrypted ones."""

    name = "websocket_review"
    description = "Surface WebSocket endpoints and flag insecure (ws://) ones."

    async def run(self, ctx: NetworkContext) -> ReconResult:
        result = ReconResult(task_id="", module=self.name)
        cap = _cap(ctx.settings)
        seen: set[str] = set()
        insecure = 0
        try:
            # WebSocket URLs can hide in endpoint/URL values and header values
            # (e.g. Sec-WebSocket-* or Location); scan both.
            corpus = [e.value for e in ctx.endpoints]
            corpus += [str(h.attributes.get("value", h.value)) for h in ctx.headers]
            for text in corpus:
                if len(seen) >= cap:
                    break
                for url, secure in websocket_endpoints(text):
                    key = f"{AssetType.WEBSOCKET.value}:{url.lower()}"
                    if key in seen:
                        continue
                    seen.add(key)
                    if not secure:
                        insecure += 1
                    result.assets.append(
                        Asset(
                            type=AssetType.WEBSOCKET,
                            value=url,
                            source=self.name,
                            attributes={"secure": secure},
                            confidence=0.85,
                        )
                    )
            if seen:
                result.notes.append(
                    f"Found {len(seen)} WebSocket endpoint(s) ({insecure} insecure)."
                )
        except Exception as exc:  # noqa: BLE001 - resilience contract
            result.errors.append(f"websocket review failed: {exc}")
        return result


class CORSHygieneModule(NetworkModule):
    """Flag dangerous cross-origin (CORS) response-header configurations.

    Rather than mint a new asset type, this re-emits the analyzed
    ``Access-Control-Allow-Origin`` HEADER asset with an ``attributes``
    ``cors_issues`` list; the knowledge graph merges it onto the existing header
    asset by key, so downstream analysis reads the issues straight off the header.
    """

    name = "cors_hygiene"
    description = "Flag dangerous CORS response-header configurations."

    async def run(self, ctx: NetworkContext) -> ReconResult:
        result = ReconResult(task_id="", module=self.name)
        try:
            # Credentialed responses (ACAC: true) turn a wildcard/null origin from
            # an information-exposure into an authenticated-data-exposure.
            credentialed = any(
                str(h.attributes.get("name", "")).lower() == "access-control-allow-credentials"
                and str(h.attributes.get("value", "")).strip().lower() == "true"
                for h in ctx.headers
            )
            flagged = 0
            for h in ctx.headers:
                name = str(h.attributes.get("name", "")).lower()
                if name != "access-control-allow-origin":
                    continue
                value = str(h.attributes.get("value", ""))
                issues = cors_issues(name, value, credentialed=credentialed)
                if not issues:
                    continue
                flagged += 1
                # Re-emit with the SAME key (reuse h.value) so add_asset merges the
                # cors_issues attribute onto the existing header asset.
                result.assets.append(
                    Asset(
                        type=AssetType.HEADER,
                        value=h.value,
                        source=self.name,
                        attributes={
                            "name": name,
                            "value": value,
                            "cors_issues": issues,
                        },
                        confidence=h.confidence,
                    )
                )
            if flagged:
                result.notes.append(f"Flagged {flagged} CORS misconfiguration(s).")
        except Exception as exc:  # noqa: BLE001 - resilience contract
            result.errors.append(f"cors hygiene failed: {exc}")
        return result


def build_network_modules(settings: Settings | None = None) -> list[NetworkModule]:
    """Return the enabled network modules, honouring the per-capability toggles.

    With no settings (or all toggles on) the full set is returned. The modules are
    cheap, dependency-free objects, so construction is always safe.
    """
    net = settings.network if settings is not None else None
    modules: list[NetworkModule] = []
    if net is None or net.decode_jwt:
        modules.append(JWTInspectionModule())
    if net is None or net.classify_apis:
        modules.append(APIClassificationModule())
    if net is None or net.flag_insecure_websocket:
        modules.append(WebSocketReviewModule())
    # CORS hygiene has no dedicated toggle; it is part of header analysis and
    # always runs when the network agent is enabled.
    modules.append(CORSHygieneModule())
    return modules
