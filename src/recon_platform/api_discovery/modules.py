"""Concrete API-discovery modules + the ``build_api_modules`` factory.

Each module is a thin, dependency-free wrapper that applies the pure helpers in
:mod:`recon_platform.api_discovery.detectors` to the asset snapshot the
:class:`~recon_platform.agents.api_discovery.APIDiscoveryAgent` gathered from the
knowledge graph, and returns new API-layer assets/relations. Nothing here issues
network I/O — the modules only reason over what earlier agents already observed —
so the whole family is safe to run offline and degrades to empty results when the
graph holds nothing relevant.

Modules follow the same resilience contract as every other family: analysis
errors are captured in ``result.errors`` rather than raised, so one failing
module never aborts a run.

New asset types produced (documented in :mod:`recon_platform.domain.enums`):

* ``API`` — a discovered API service (``attributes["style"]`` = rest / graphql /
  soap / grpc, plus base path, version, resources, endpoint count).
* ``API_PARAMETER`` — an inferred request parameter (``attributes["location"]`` =
  query / path).
* ``AUTH_SCHEME`` — a detected authentication scheme (bearer / basic / digest /
  api_key / cookie).
"""

from __future__ import annotations

from recon_platform.api_discovery.base import APIDiscoveryContext, APIModule
from recon_platform.api_discovery.detectors import (
    api_style,
    detect_auth_schemes,
    extract_parameters,
    rest_signature,
)
from recon_platform.core.config import Settings
from recon_platform.domain.enums import AssetType, RelationType
from recon_platform.domain.schemas import Asset, ReconResult, Relation


def _cap(settings: Settings) -> int:
    """Per-module item budget (defensive against pathological inputs)."""
    return max(0, int(settings.api_discovery.max_items))


class RESTInferenceModule(APIModule):
    """Group endpoint URLs into REST APIs and infer resources + parameters."""

    name = "rest_inference"
    description = "Infer REST APIs (base path / version / resources / parameters) from endpoints."

    async def run(self, ctx: APIDiscoveryContext) -> ReconResult:
        result = ReconResult(task_id="", module=self.name)
        cap = _cap(ctx.settings)
        # group key -> aggregate state
        groups: dict[str, dict] = {}
        params: dict[str, Asset] = {}
        try:
            for ep in ctx.endpoints[: cap or None]:
                if api_style(ep.value) != "rest":
                    continue
                sig = rest_signature(ep.value)
                if sig is None:
                    continue
                gkey = f"{sig['host']}{sig['base_path']}"
                g = groups.setdefault(
                    gkey,
                    {
                        "host": sig["host"],
                        "base_path": sig["base_path"],
                        "version": sig["version"],
                        "resources": set(),
                        "endpoint_keys": [],
                    },
                )
                if sig["resource"]:
                    g["resources"].add(sig["resource"])
                if sig["version"] and not g["version"]:
                    g["version"] = sig["version"]
                g["endpoint_keys"].append(ep.key)

                for p in extract_parameters(ep.value):
                    pvalue = f"{p['name']} ({p['location']})"
                    pkey = f"{AssetType.API_PARAMETER.value}:{pvalue.lower()}"
                    if pkey not in params:
                        params[pkey] = Asset(
                            type=AssetType.API_PARAMETER,
                            value=pvalue,
                            source=self.name,
                            attributes={
                                "name": p["name"],
                                "location": p["location"],
                                "example": p["example"],
                            },
                            confidence=0.7,
                        )

            for gkey, g in groups.items():
                api_asset = Asset(
                    type=AssetType.API,
                    value=gkey,
                    source=self.name,
                    attributes={
                        "style": "rest",
                        "host": g["host"],
                        "base_path": g["base_path"],
                        "version": g["version"],
                        "resources": sorted(g["resources"]),
                        "endpoint_count": len(g["endpoint_keys"]),
                    },
                    confidence=0.8,
                )
                result.assets.append(api_asset)
                for ekey in g["endpoint_keys"]:
                    result.relations.append(
                        Relation(
                            source_key=api_asset.key,
                            target_key=ekey,
                            type=RelationType.EXPOSES,
                        )
                    )

            result.assets.extend(params.values())
            if groups:
                result.notes.append(
                    f"Inferred {len(groups)} REST API(s), {len(params)} parameter(s)."
                )
        except Exception as exc:  # noqa: BLE001 - resilience contract
            result.errors.append(f"rest inference failed: {exc}")
        return result


class GraphQLDiscoveryModule(APIModule):
    """Surface GraphQL APIs (and likely introspection exposure)."""

    name = "graphql_discovery"
    description = "Discover GraphQL APIs from classified traffic and endpoint paths."

    async def run(self, ctx: APIDiscoveryContext) -> ReconResult:
        result = ReconResult(task_id="", module=self.name)
        cap = _cap(ctx.settings)
        seen: set[str] = set()
        try:
            candidates = list(ctx.endpoints)
            # The Network agent's API_ENDPOINT(graphql) assets are strong signals.
            candidates += [
                a for a in ctx.api_endpoints if a.attributes.get("api_type") == "graphql"
            ]
            for a in candidates:
                if len(seen) >= cap:
                    break
                if a.attributes.get("api_type") != "graphql" and api_style(a.value) != "graphql":
                    continue
                key = f"{AssetType.API.value}:{a.value.lower()}"
                if key in seen:
                    continue
                seen.add(key)
                api_asset = Asset(
                    type=AssetType.API,
                    value=a.value,
                    source=self.name,
                    attributes={"style": "graphql", "introspection_risk": True},
                    confidence=0.8,
                )
                result.assets.append(api_asset)
                result.relations.append(
                    Relation(
                        source_key=api_asset.key,
                        target_key=a.key,
                        type=RelationType.EXPOSES,
                    )
                )
            if seen:
                result.notes.append(f"Discovered {len(seen)} GraphQL API(s).")
        except Exception as exc:  # noqa: BLE001 - resilience contract
            result.errors.append(f"graphql discovery failed: {exc}")
        return result


class SOAPGRPCDiscoveryModule(APIModule):
    """Detect SOAP (?wsdl / .asmx / .svc) and gRPC endpoints."""

    name = "soap_grpc_discovery"
    description = "Detect SOAP and gRPC APIs from endpoint paths."

    async def run(self, ctx: APIDiscoveryContext) -> ReconResult:
        result = ReconResult(task_id="", module=self.name)
        cap = _cap(ctx.settings)
        seen: set[str] = set()
        try:
            for ep in ctx.endpoints:
                if len(seen) >= cap:
                    break
                style = api_style(ep.value)
                if style not in ("soap", "grpc"):
                    continue
                key = f"{AssetType.API.value}:{ep.value.lower()}"
                if key in seen:
                    continue
                seen.add(key)
                api_asset = Asset(
                    type=AssetType.API,
                    value=ep.value,
                    source=self.name,
                    attributes={"style": style},
                    confidence=0.75,
                )
                result.assets.append(api_asset)
                result.relations.append(
                    Relation(
                        source_key=api_asset.key,
                        target_key=ep.key,
                        type=RelationType.EXPOSES,
                    )
                )
            if seen:
                result.notes.append(f"Discovered {len(seen)} SOAP/gRPC API(s).")
        except Exception as exc:  # noqa: BLE001 - resilience contract
            result.errors.append(f"soap/grpc discovery failed: {exc}")
        return result


class AuthSchemeModule(APIModule):
    """Detect authentication schemes from request/response headers."""

    name = "auth_scheme_detection"
    description = "Detect authentication schemes (Bearer / Basic / API-key / cookie) from headers."

    async def run(self, ctx: APIDiscoveryContext) -> ReconResult:
        result = ReconResult(task_id="", module=self.name)
        try:
            pairs = [
                (str(h.attributes.get("name", "")), str(h.attributes.get("value", "")))
                for h in ctx.headers
            ]
            for scheme in detect_auth_schemes(pairs):
                result.assets.append(
                    Asset(
                        type=AssetType.AUTH_SCHEME,
                        value=scheme["scheme"],
                        source=self.name,
                        attributes={"detail": scheme["detail"]},
                        confidence=0.8,
                    )
                )
            if result.assets:
                result.notes.append(f"Detected {len(result.assets)} auth scheme(s).")
        except Exception as exc:  # noqa: BLE001 - resilience contract
            result.errors.append(f"auth-scheme detection failed: {exc}")
        return result


def build_api_modules(settings: Settings | None = None) -> list[APIModule]:
    """Return the enabled API-discovery modules, honouring the per-capability toggles.

    With no settings (or all toggles on) the full set is returned. The modules are
    cheap, dependency-free objects, so construction is always safe.
    """
    api = settings.api_discovery if settings is not None else None
    modules: list[APIModule] = []
    if api is None or api.infer_rest:
        modules.append(RESTInferenceModule())
    if api is None or api.discover_graphql:
        modules.append(GraphQLDiscoveryModule())
    if api is None or api.discover_soap_grpc:
        modules.append(SOAPGRPCDiscoveryModule())
    if api is None or api.detect_auth:
        modules.append(AuthSchemeModule())
    return modules
