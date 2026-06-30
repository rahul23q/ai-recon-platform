"""Concrete external-tool wrappers + the default tool set.

Ten best-of-breed security tools, each wrapped behind the :class:`ExternalTool`
contract: build a command line, then normalize the captured stdout into the
platform's common domain models. Parsers are written defensively — unknown keys,
blank lines, and partial output are ignored rather than raised — and are the unit
the hermetic tests exercise directly with canned output (no real binary).

Output-format notes (kept simple and stable):

* **httpx / nuclei** — newline-delimited JSON (``-json`` / ``-jsonl``).
* **ffuf** — a single JSON document (``-of json``) with a ``results`` array.
* **subfinder / amass / gau / katana / dirsearch** — plain text lines.
* **naabu** — ``host:port`` lines; **nmap** — grepable output (``-oG -``).
"""

from __future__ import annotations

import json
import re

from recon_platform.active_recon.base import ExternalTool
from recon_platform.active_recon.models import ToolExecution
from recon_platform.core.config import Settings
from recon_platform.domain.enums import AssetType, RelationType
from recon_platform.domain.schemas import Asset, ReconResult, Relation

# Valid DNS hostname (reused shape from the passive recon modules).
_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](-?[a-z0-9])*\.)+[a-z]{2,}$")
# nuclei severities map 1:1 onto the platform Severity values.
_NUCLEI_SEVERITIES = {"info", "low", "medium", "high", "critical"}


def _lines(text: str) -> list[str]:
    return [ln.strip() for ln in text.splitlines() if ln.strip()]


def _json_lines(text: str) -> list[dict]:
    out: list[dict] = []
    for ln in _lines(text):
        try:
            obj = json.loads(ln)
        except (ValueError, TypeError):
            continue
        if isinstance(obj, dict):
            out.append(obj)
    return out


def _url_key(url: str) -> str:
    return f"{AssetType.URL.value}:{url.lower()}"


def _domain_key(host: str) -> str:
    return f"{AssetType.DOMAIN.value}:{host.lower()}"


class HttpxTool(ExternalTool):
    name = "httpx"
    binary = "httpx"
    description = "Probe hosts for live HTTP services, titles, and technologies (ProjectDiscovery)."

    def build_command(self, target: str, settings: Settings) -> list[str]:
        return ["httpx", "-silent", "-json", "-u", target]

    def parse(self, execution: ToolExecution, target: str) -> ReconResult:
        result = ReconResult(task_id="", module=self.name)
        for row in _json_lines(execution.stdout):
            url = str(row.get("url") or row.get("input") or "").strip()
            if not url:
                continue
            attrs = {"via": "httpx"}
            if row.get("status_code") is not None:
                attrs["status_code"] = row["status_code"]
            for key in ("title", "webserver", "content_type", "host"):
                if row.get(key):
                    attrs[key] = row[key]
            result.assets.append(
                Asset(type=AssetType.URL, value=url, source=self.name, attributes=attrs)
            )
            techs = row.get("tech") or row.get("technologies") or []
            for tech in techs if isinstance(techs, list) else []:
                result.assets.append(
                    Asset(
                        type=AssetType.TECHNOLOGY,
                        value=str(tech).lower(),
                        source=self.name,
                        attributes={"via": "httpx"},
                    )
                )
        result.notes.append(f"httpx probed {len(result.assets)} live result(s).")
        return result


class SubfinderTool(ExternalTool):
    name = "subfinder"
    binary = "subfinder"
    description = "Passive subdomain enumeration (ProjectDiscovery)."

    def build_command(self, target: str, settings: Settings) -> list[str]:
        return ["subfinder", "-silent", "-d", target]

    def parse(self, execution: ToolExecution, target: str) -> ReconResult:
        return _parse_subdomains(execution.stdout, target, self.name)


class AmassTool(ExternalTool):
    name = "amass"
    binary = "amass"
    description = "In-depth subdomain enumeration (OWASP Amass, passive mode)."

    def build_command(self, target: str, settings: Settings) -> list[str]:
        return ["amass", "enum", "-passive", "-d", target]

    def parse(self, execution: ToolExecution, target: str) -> ReconResult:
        return _parse_subdomains(execution.stdout, target, self.name)


class NaabuTool(ExternalTool):
    name = "naabu"
    binary = "naabu"
    description = "Fast SYN/CONNECT port scanner (ProjectDiscovery)."

    def build_command(self, target: str, settings: Settings) -> list[str]:
        cmd = ["naabu", "-silent", "-host", target]
        if settings.active_recon.rate_limit:
            cmd += ["-rate", str(settings.active_recon.rate_limit)]
        return cmd

    def parse(self, execution: ToolExecution, target: str) -> ReconResult:
        result = ReconResult(task_id="", module=self.name)
        for ln in _lines(execution.stdout):
            if ":" not in ln:
                continue
            host, _, port = ln.rpartition(":")
            if not port.isdigit():
                continue
            asset = Asset(
                type=AssetType.PORT,
                value=ln,
                source=self.name,
                attributes={"host": host, "port": int(port), "via": "naabu"},
            )
            result.assets.append(asset)
            result.relations.append(
                Relation(
                    source_key=_domain_key(host),
                    target_key=asset.key,
                    type=RelationType.EXPOSES,
                )
            )
        result.notes.append(f"naabu found {len(result.assets)} open port(s).")
        return result


class KatanaTool(ExternalTool):
    name = "katana"
    binary = "katana"
    description = "Next-gen crawling / endpoint discovery (ProjectDiscovery)."

    def build_command(self, target: str, settings: Settings) -> list[str]:
        return ["katana", "-silent", "-u", target]

    def parse(self, execution: ToolExecution, target: str) -> ReconResult:
        return _parse_urls(execution.stdout, self.name, AssetType.ENDPOINT, confidence=0.9)


class GauTool(ExternalTool):
    name = "gau"
    binary = "gau"
    description = "Fetch known URLs from Wayback/OTX/Common Crawl (getallurls)."

    def build_command(self, target: str, settings: Settings) -> list[str]:
        return ["gau", "--subs", target]

    def parse(self, execution: ToolExecution, target: str) -> ReconResult:
        return _parse_urls(execution.stdout, self.name, AssetType.URL, confidence=0.6)


class DirsearchTool(ExternalTool):
    name = "dirsearch"
    binary = "dirsearch"
    description = "Web path / content brute-forcing (built-in wordlist)."

    # Matches dirsearch plain output, e.g. "[12:00:00] 200 -    1KB - /admin/".
    _LINE = re.compile(r"\b([1-5]\d{2})\b.*?(/\S*)")

    def build_command(self, target: str, settings: Settings) -> list[str]:
        url = target if target.startswith(("http://", "https://")) else f"https://{target}"
        return ["dirsearch", "-u", url, "-q"]

    def parse(self, execution: ToolExecution, target: str) -> ReconResult:
        result = ReconResult(task_id="", module=self.name)
        base = target if target.startswith(("http://", "https://")) else f"https://{target}"
        seen: set[str] = set()
        for ln in _lines(execution.stdout):
            m = self._LINE.search(ln)
            if not m:
                continue
            status, path = m.group(1), m.group(2)
            url = path if path.startswith("http") else base.rstrip("/") + path
            if url in seen:
                continue
            seen.add(url)
            result.assets.append(
                Asset(
                    type=AssetType.ENDPOINT,
                    value=url,
                    source=self.name,
                    attributes={"status_code": int(status), "via": "dirsearch"},
                )
            )
        result.notes.append(f"dirsearch discovered {len(result.assets)} path(s).")
        return result


class FfufTool(ExternalTool):
    name = "ffuf"
    binary = "ffuf"
    description = "Fast web fuzzer for content/parameter discovery."

    def build_command(self, target: str, settings: Settings) -> list[str]:
        wordlist = settings.active_recon.wordlist
        if not wordlist:
            return []  # no wordlist configured ⇒ skip cleanly
        url = target if target.startswith(("http://", "https://")) else f"https://{target}"
        url = url.rstrip("/") + "/FUZZ"
        return ["ffuf", "-u", url, "-w", wordlist, "-of", "json", "-o", "/dev/stdout", "-s"]

    def parse(self, execution: ToolExecution, target: str) -> ReconResult:
        result = ReconResult(task_id="", module=self.name)
        try:
            doc = json.loads(execution.stdout or "{}")
        except (ValueError, TypeError):
            doc = {}
        for row in doc.get("results", []) if isinstance(doc, dict) else []:
            url = str(row.get("url", "")).strip()
            if not url:
                continue
            result.assets.append(
                Asset(
                    type=AssetType.ENDPOINT,
                    value=url,
                    source=self.name,
                    attributes={
                        "status_code": row.get("status"),
                        "length": row.get("length"),
                        "via": "ffuf",
                    },
                )
            )
        result.notes.append(f"ffuf found {len(result.assets)} hit(s).")
        return result


class NucleiTool(ExternalTool):
    name = "nuclei"
    binary = "nuclei"
    description = "Template-based vulnerability scanner (ProjectDiscovery)."

    def build_command(self, target: str, settings: Settings) -> list[str]:
        cmd = ["nuclei", "-silent", "-jsonl", "-u", target]
        if settings.active_recon.nuclei_severity:
            cmd += ["-severity", settings.active_recon.nuclei_severity]
        if settings.active_recon.rate_limit:
            cmd += ["-rate-limit", str(settings.active_recon.rate_limit)]
        return cmd

    def parse(self, execution: ToolExecution, target: str) -> ReconResult:
        result = ReconResult(task_id="", module=self.name)
        for row in _json_lines(execution.stdout):
            info = row.get("info", {}) if isinstance(row.get("info"), dict) else {}
            template = str(row.get("template-id") or row.get("templateID") or "").strip()
            name = str(info.get("name") or template or "nuclei match").strip()
            severity = str(info.get("severity", "info")).lower()
            if severity not in _NUCLEI_SEVERITIES:
                severity = "info"
            matched = str(row.get("matched-at") or row.get("host") or target).strip()
            vuln = Asset(
                type=AssetType.VULNERABILITY,
                value=f"{template or name}@{matched}",
                source=self.name,
                attributes={
                    "name": name,
                    "template": template,
                    "severity": severity,
                    "matched_at": matched,
                    "type": str(row.get("type", "")),
                    "via": "nuclei",
                },
            )
            result.assets.append(vuln)
            if matched:
                result.relations.append(
                    Relation(
                        source_key=vuln.key,
                        target_key=_url_key(matched),
                        type=RelationType.AFFECTS,
                    )
                )
        result.notes.append(f"nuclei reported {len(result.assets)} match(es).")
        return result


class NmapTool(ExternalTool):
    name = "nmap"
    binary = "nmap"
    description = "Port scan + service/version detection (grepable output)."

    # Grepable "Ports:" entries: 22/open/tcp//ssh//OpenSSH 8.9p1/
    _PORT = re.compile(r"(\d+)/(open|open\|filtered)/(tcp|udp)//([^/]*)//([^/,]*)")

    def build_command(self, target: str, settings: Settings) -> list[str]:
        return ["nmap", "-Pn", "-sV", "-oG", "-", target]

    def parse(self, execution: ToolExecution, target: str) -> ReconResult:
        result = ReconResult(task_id="", module=self.name)
        host = target
        for ln in _lines(execution.stdout):
            hm = re.search(r"Host:\s+(\S+)", ln)
            if hm:
                host = hm.group(1)
            if "Ports:" not in ln:
                continue
            for port, state, proto, service, product in self._PORT.findall(ln):
                asset = Asset(
                    type=AssetType.SERVICE,
                    value=f"{host}:{port}",
                    source=self.name,
                    attributes={
                        "host": host,
                        "port": int(port),
                        "protocol": proto,
                        "state": state,
                        "service": service or "unknown",
                        "product": product.strip(),
                        "via": "nmap",
                    },
                )
                result.assets.append(asset)
                result.relations.append(
                    Relation(
                        source_key=_domain_key(host),
                        target_key=asset.key,
                        type=RelationType.EXPOSES,
                    )
                )
        result.notes.append(f"nmap detected {len(result.assets)} service(s).")
        return result


# -- shared parse helpers ---------------------------------------------------
def _parse_subdomains(stdout: str, target: str, source: str) -> ReconResult:
    result = ReconResult(task_id="", module=source)
    suffix = "." + target.lower()
    seen: set[str] = set()
    for raw in _lines(stdout):
        host = raw.lower().lstrip("*.")
        if host in seen or not _HOSTNAME_RE.match(host):
            continue
        if host != target.lower() and not host.endswith(suffix):
            continue
        seen.add(host)
        result.assets.append(
            Asset(type=AssetType.SUBDOMAIN, value=host, source=source)
        )
        result.relations.append(
            Relation(
                source_key=f"{AssetType.SUBDOMAIN.value}:{host}",
                target_key=_domain_key(target),
                type=RelationType.SUBDOMAIN_OF,
            )
        )
    result.notes.append(f"{source} enumerated {len(seen)} subdomain(s).")
    return result


def _parse_urls(stdout: str, source: str, asset_type: AssetType, confidence: float) -> ReconResult:
    result = ReconResult(task_id="", module=source)
    seen: set[str] = set()
    for raw in _lines(stdout):
        if not raw.startswith(("http://", "https://")):
            continue
        if raw in seen:
            continue
        seen.add(raw)
        result.assets.append(
            Asset(
                type=asset_type,
                value=raw,
                source=source,
                attributes={"via": source},
                confidence=confidence,
            )
        )
    result.notes.append(f"{source} yielded {len(seen)} URL(s).")
    return result


def build_active_tools() -> list[ExternalTool]:
    """Return the default ordered active-recon tool set (all ten wrappers)."""
    return [
        SubfinderTool(),
        AmassTool(),
        HttpxTool(),
        NaabuTool(),
        NmapTool(),
        KatanaTool(),
        GauTool(),
        DirsearchTool(),
        FfufTool(),
        NucleiTool(),
    ]


#: Convenience map of tool name → class for discovery / selection.
ACTIVE_TOOLS = {
    t.name: type(t) for t in build_active_tools()
}
