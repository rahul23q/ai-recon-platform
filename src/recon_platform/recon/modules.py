"""Concrete passive recon modules.

All modules are passive: DNS resolution, fetching publicly served documents
(robots.txt, the home page), and querying public OSINT datasets (Certificate
Transparency via crt.sh, the Wayback Machine). None probe for vulnerabilities.

Each module degrades gracefully — network failures are recorded in
``result.errors`` so the pipeline always completes.
"""

from __future__ import annotations

import re
import socket

import anyio

from recon_platform.core.logging import get_logger
from recon_platform.domain.enums import AssetType, RelationType
from recon_platform.domain.schemas import Asset, ReconResult, Relation
from recon_platform.recon.base import ModuleContext, ReconModule

log = get_logger(__name__)

# Valid DNS hostname (labels of letters/digits/hyphens). Excludes emails,
# whitespace, and other Certificate Transparency name artifacts.
_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](-?[a-z0-9])*\.)+[a-z]{2,}$")

# Security headers we expect a hardened site to set (absence is reported).
SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]

# Naive technology fingerprints keyed by response header / body markers.
TECH_SIGNATURES = {
    "nginx": ("header", "server", "nginx"),
    "apache": ("header", "server", "apache"),
    "cloudflare": ("header", "server", "cloudflare"),
    "express": ("header", "x-powered-by", "express"),
    "php": ("header", "x-powered-by", "php"),
    "wordpress": ("body", "", "wp-content"),
    "react": ("body", "", "data-reactroot"),
}


class DNSModule(ReconModule):
    name = "dns"
    description = "Resolve A/AAAA records for the target host."

    async def run(self, ctx: ModuleContext) -> ReconResult:
        result = ReconResult(task_id="", module=self.name)
        domain = Asset(type=AssetType.DOMAIN, value=ctx.target, source=self.name)
        result.assets.append(domain)
        try:
            infos = await anyio.to_thread.run_sync(
                lambda: socket.getaddrinfo(ctx.target, None)
            )
            seen: set[str] = set()
            for info in infos:
                ip = info[4][0]
                if ip in seen:
                    continue
                seen.add(ip)
                ip_asset = Asset(type=AssetType.IP, value=ip, source=self.name)
                result.assets.append(ip_asset)
                result.relations.append(
                    Relation(
                        source_key=domain.key,
                        target_key=ip_asset.key,
                        type=RelationType.RESOLVES_TO,
                    )
                )
            result.notes.append(f"Resolved {len(seen)} unique IP(s).")
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"DNS resolution failed: {exc}")
        return result


class HTTPHeadersModule(ReconModule):
    name = "http_headers"
    description = "Fetch the home page and analyze HTTP + security headers."

    async def run(self, ctx: ModuleContext) -> ReconResult:
        result = ReconResult(task_id="", module=self.name)
        url = f"https://{ctx.target}/"
        try:
            # follow_redirects=True ⇒ ``resp`` is the FINAL response after the
            # redirect chain; header analysis must only consider this response,
            # never an intermediate 301/302 (which rarely carries security
            # headers and would otherwise produce false "missing" results).
            resp = await ctx.http.get(url, follow_redirects=True)
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"HTTP request to {url} failed: {exc}")
            return result

        redirect_chain = [str(r.url) for r in resp.history]
        url_asset = Asset(
            type=AssetType.URL,
            value=str(resp.url),
            source=self.name,
            attributes={
                "status_code": resp.status_code,
                "final": True,
                "redirect_chain": redirect_chain,
            },
        )
        result.assets.append(url_asset)

        # Record each header of the FINAL response. Header names are
        # case-insensitive (RFC 9110): normalize to lowercase so downstream
        # comparison can never miss a present header due to casing. We store both
        # presence (the asset exists) and the actual value.
        for header, value in resp.headers.items():
            name = header.strip().lower()
            result.assets.append(
                Asset(
                    type=AssetType.HEADER,
                    value=f"{name}: {value}",
                    source=self.name,
                    attributes={
                        "name": name,
                        "value": value,
                        "present": True,
                        "status_code": resp.status_code,
                        "final": True,
                    },
                )
            )

        present = {h.strip().lower() for h in resp.headers}
        missing = [h for h in SECURITY_HEADERS if h not in present]
        if missing:
            result.notes.append(
                "Security headers absent from passive HTTP response (pending "
                "cross-source verification): " + ", ".join(missing)
            )
        result.notes.append(f"Final HTTP {resp.status_code} from {resp.url}")

        # Stash the body for the fingerprint module via the context cache.
        ctx.__dict__.setdefault("_cache", {})["home_html"] = resp.text[:200_000]
        ctx.__dict__["_cache"]["home_headers"] = dict(resp.headers)
        return result


class RobotsModule(ReconModule):
    name = "robots"
    description = "Parse robots.txt for disclosed paths."

    async def run(self, ctx: ModuleContext) -> ReconResult:
        result = ReconResult(task_id="", module=self.name)
        url = f"https://{ctx.target}/robots.txt"
        try:
            resp = await ctx.http.get(url, follow_redirects=True)
            if resp.status_code != 200 or "text" not in resp.headers.get("content-type", ""):
                result.notes.append("No robots.txt served.")
                return result
            paths = re.findall(r"(?im)^(?:dis)?allow:\s*(\S+)", resp.text)
            for path in sorted(set(paths)):
                result.assets.append(
                    Asset(
                        type=AssetType.ENDPOINT,
                        value=f"https://{ctx.target}{path}",
                        source=self.name,
                        attributes={"from": "robots.txt"},
                    )
                )
            result.notes.append(f"robots.txt disclosed {len(set(paths))} path(s).")
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"robots.txt fetch failed: {exc}")
        return result


class CrtShModule(ReconModule):
    name = "crtsh_ct"
    description = "Enumerate subdomains via Certificate Transparency (crt.sh)."

    async def run(self, ctx: ModuleContext) -> ReconResult:
        result = ReconResult(task_id="", module=self.name)
        url = f"https://crt.sh/?q=%25.{ctx.target}&output=json"
        try:
            resp = await ctx.http.get(url, follow_redirects=True)
            if resp.status_code != 200:
                result.notes.append(f"crt.sh returned HTTP {resp.status_code}.")
                return result
            rows = resp.json()
            subs: set[str] = set()
            suffix = "." + ctx.target
            for row in rows:
                for name in str(row.get("name_value", "")).splitlines():
                    name = name.strip().lower().lstrip("*.")
                    # Reject CT artifacts: emails, CN strings with spaces, and
                    # look-alike domains. Require a valid hostname that is a
                    # genuine subdomain (foo.example.com), not testexample.com.
                    if not _HOSTNAME_RE.match(name):
                        continue
                    if name.endswith(suffix):
                        subs.add(name)
            for sub in sorted(subs):
                result.assets.append(
                    Asset(type=AssetType.SUBDOMAIN, value=sub, source=self.name)
                )
                result.relations.append(
                    Relation(
                        source_key=f"{AssetType.SUBDOMAIN.value}:{sub}",
                        target_key=f"{AssetType.DOMAIN.value}:{ctx.target}",
                        type=RelationType.SUBDOMAIN_OF,
                    )
                )
            result.notes.append(f"CT logs revealed {len(subs)} subdomain(s).")
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"crt.sh query failed: {exc}")
        return result


class WaybackModule(ReconModule):
    name = "wayback"
    description = "Collect historical URLs from the Wayback Machine CDX API."

    async def run(self, ctx: ModuleContext) -> ReconResult:
        result = ReconResult(task_id="", module=self.name)
        url = (
            "https://web.archive.org/cdx/search/cdx"
            f"?url={ctx.target}/*&output=json&fl=original&collapse=urlkey&limit=200"
        )
        try:
            resp = await ctx.http.get(url, follow_redirects=True)
            if resp.status_code != 200:
                result.notes.append(f"Wayback returned HTTP {resp.status_code}.")
                return result
            rows = resp.json()
            urls = {r[0] for r in rows[1:]} if len(rows) > 1 else set()
            for u in sorted(urls)[:200]:
                result.assets.append(
                    Asset(type=AssetType.URL, value=u, source=self.name, confidence=0.6)
                )
            result.notes.append(f"Wayback yielded {len(urls)} historical URL(s).")
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"Wayback query failed: {exc}")
        return result


class TechFingerprintModule(ReconModule):
    name = "tech_fingerprint"
    description = "Identify technologies from response headers and body markers."

    async def run(self, ctx: ModuleContext) -> ReconResult:
        result = ReconResult(task_id="", module=self.name)
        cache = ctx.__dict__.get("_cache", {})
        headers = {k.lower(): str(v).lower() for k, v in cache.get("home_headers", {}).items()}
        body = cache.get("home_html", "").lower()
        if not headers and not body:
            result.notes.append("No cached response to fingerprint (run http_headers first).")
            return result

        detected: set[str] = set()
        for tech, (where, key, marker) in TECH_SIGNATURES.items():
            if where == "header" and marker in headers.get(key, ""):
                detected.add(tech)
            elif where == "body" and marker in body:
                detected.add(tech)

        for tech in sorted(detected):
            result.assets.append(
                Asset(type=AssetType.TECHNOLOGY, value=tech, source=self.name)
            )
        listed = ", ".join(sorted(detected)) or "none"
        result.notes.append(f"Fingerprinted {len(detected)} technolog(ies): {listed}.")
        return result


def build_passive_modules() -> list[ReconModule]:
    """Return the ordered default passive recon module set.

    Order matters: http_headers caches the response that tech_fingerprint reads.
    """
    return [
        DNSModule(),
        HTTPHeadersModule(),
        RobotsModule(),
        TechFingerprintModule(),
        CrtShModule(),
        WaybackModule(),
    ]


#: Convenience list of module classes for discovery/registries.
PASSIVE_MODULES = [
    DNSModule,
    HTTPHeadersModule,
    RobotsModule,
    TechFingerprintModule,
    CrtShModule,
    WaybackModule,
]
