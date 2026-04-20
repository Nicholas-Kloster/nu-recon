"""Targeted host reconnaissance.

Passive + light-touch enumeration of a single IPv4 target:
  - reverse DNS
  - Shodan host lookup (optional, env: SHODAN_API_KEY)
  - TLS certificate fetch (via stdlib ssl)
  - crt.sh certificate-transparency lookup (by hostname, not IP)
  - simple threat graph + JSON report

Authorization is the caller's responsibility.
"""
from __future__ import annotations

import json
import logging
import os
import socket
import ssl
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

import requests

log = logging.getLogger(__name__)

SHODAN_HOST_URL = "https://api.shodan.io/shodan/host/{ip}"
CRTSH_URL = "https://crt.sh/"
DEFAULT_TIMEOUT = 10
WEB_PORTS = {80, 443, 8080, 8443}


@dataclass
class Service:
    port: int
    product: str | None = None
    version: str | None = None
    transport: str | None = None
    banner: str | None = None


@dataclass
class Vulnerability:
    cve: str
    service: str
    port: int
    severity: str
    description: str


@dataclass
class HostReport:
    timestamp: str
    target_ip: str
    hostname: str | None
    geolocation: dict[str, Any]
    open_ports: list[int]
    services: list[dict[str, Any]]
    web_technologies: list[dict[str, Any]]
    vulnerabilities: list[dict[str, Any]]
    dns_records: dict[str, list[str]]
    ssl_certificate: dict[str, Any]
    threat_graph: dict[str, list[dict[str, Any]]]
    crtsh_domains: list[str]
    risk_summary: dict[str, Any]
    simulated: bool


class TargetedHostMapper:
    """Enumerate a single IP. All network calls are best-effort."""

    def __init__(
        self,
        target_ip: str,
        shodan_api_key: str | None = None,
        http_session: requests.Session | None = None,
        timeout: int = DEFAULT_TIMEOUT,
    ):
        self.target_ip = target_ip
        self.shodan_api_key = shodan_api_key or os.environ.get("SHODAN_API_KEY")
        self.http = http_session or requests.Session()
        self.timeout = timeout

        self.hostname: str | None = None
        self.geolocation: dict[str, Any] = {}
        self.open_ports: list[int] = []
        self.services: list[Service] = []
        self.web_technologies: list[dict[str, Any]] = []
        self.vulnerabilities: list[Vulnerability] = []
        self.dns_records: dict[str, list[str]] = {}
        self.ssl_certificate: dict[str, Any] = {}
        self.threat_graph: dict[str, list[dict[str, Any]]] = {}
        self.crtsh_domains: list[str] = []
        self.simulated = False

    def resolve_hostname(self) -> str | None:
        try:
            self.hostname = socket.gethostbyaddr(self.target_ip)[0]
            log.info("reverse DNS: %s", self.hostname)
        except (socket.herror, socket.gaierror) as exc:
            log.info("no PTR record for %s (%s)", self.target_ip, exc)
            self.hostname = None
        return self.hostname

    def query_shodan(self) -> bool:
        """Return True if real data was fetched, False if simulated fallback used."""
        if not self.shodan_api_key:
            log.warning("SHODAN_API_KEY not set; skipping Shodan lookup")
            self.simulated = True
            self._load_simulated_shodan()
            return False

        url = SHODAN_HOST_URL.format(ip=self.target_ip)
        try:
            resp = self.http.get(url, params={"key": self.shodan_api_key}, timeout=self.timeout)
        except requests.RequestException as exc:
            log.error("Shodan request failed: %s", exc)
            return False

        if resp.status_code != 200:
            log.error("Shodan returned %s: %s", resp.status_code, resp.text[:200])
            return False

        data = resp.json()
        self._ingest_shodan(data)
        return True

    def _load_simulated_shodan(self) -> None:
        """Load clearly-labeled simulated data. Never pretend to be real."""
        self.open_ports = [22, 80, 443]
        self.services = [
            Service(port=22, product="OpenSSH", version="(simulated)"),
            Service(port=80, product="nginx", version="(simulated)"),
            Service(port=443, product="nginx", version="(simulated)"),
        ]
        self.geolocation = {"country": None, "city": None, "org": "(simulated)", "isp": None}
        self._extract_web_technologies()

    def _ingest_shodan(self, data: dict[str, Any]) -> None:
        self.open_ports = sorted(set(data.get("ports") or []))
        self.services = [
            Service(
                port=s.get("port"),
                product=s.get("product"),
                version=s.get("version"),
                transport=s.get("transport"),
                banner=(s.get("data") or "")[:500] or None,
            )
            for s in (data.get("data") or [])
            if s.get("port") is not None
        ]
        self.geolocation = {
            "country": data.get("country_name"),
            "city": data.get("city"),
            "org": data.get("org"),
            "isp": data.get("isp"),
        }
        hostnames = data.get("hostnames") or []
        if hostnames and not self.hostname:
            self.hostname = hostnames[0]
        self._extract_web_technologies()

    def _extract_web_technologies(self) -> None:
        self.web_technologies = [
            {"port": s.port, "server": s.product or "unknown", "version": s.version or ""}
            for s in self.services
            if s.port in WEB_PORTS
        ]

    def query_ssl_certificate(self, port: int = 443) -> dict[str, Any]:
        """Fetch peer cert via stdlib. Works for any TLS port."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((self.target_ip, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.hostname or self.target_ip) as tls:
                    der = tls.getpeercert(binary_form=True)
                    parsed = tls.getpeercert()
        except (socket.error, ssl.SSLError, OSError) as exc:
            log.info("TLS cert fetch failed on %s:%s — %s", self.target_ip, port, exc)
            return {}

        self.ssl_certificate = {
            "port": port,
            "subject": _flatten_cert_name(parsed.get("subject", [])),
            "issuer": _flatten_cert_name(parsed.get("issuer", [])),
            "not_before": parsed.get("notBefore"),
            "not_after": parsed.get("notAfter"),
            "serial_number": parsed.get("serialNumber"),
            "san": [v for k, v in parsed.get("subjectAltName", []) if k in ("DNS", "IP Address")],
            "der_sha256_bytes": len(der) if der else 0,
        }
        return self.ssl_certificate

    def query_crt_sh(self, identity: str | None = None) -> list[str]:
        """Query crt.sh by domain (crt.sh does not reliably index by IP).

        Falls back to the resolved hostname if no identity is passed.
        """
        target = identity or self.hostname
        if not target:
            log.info("crt.sh skipped: no hostname to query")
            return []

        try:
            resp = self.http.get(
                CRTSH_URL, params={"q": target, "output": "json"}, timeout=self.timeout
            )
        except requests.RequestException as exc:
            log.error("crt.sh request failed: %s", exc)
            return []

        if resp.status_code != 200:
            log.error("crt.sh returned %s", resp.status_code)
            return []

        try:
            rows = resp.json()
        except ValueError:
            log.error("crt.sh returned non-JSON body")
            return []

        domains: set[str] = set()
        for row in rows:
            for name in (row.get("name_value") or "").split("\n"):
                name = name.strip().lstrip("*.")
                if name:
                    domains.add(name)
        self.crtsh_domains = sorted(domains)
        log.info("crt.sh: %d unique names", len(self.crtsh_domains))
        return self.crtsh_domains

    def build_threat_graph(self) -> dict[str, list[dict[str, Any]]]:
        graph: dict[str, list[dict[str, Any]]] = {}
        if 22 in self.open_ports:
            graph["ssh"] = [{
                "threat": "credential-based auth exposure",
                "impact": "interactive session",
                "likelihood": "medium",
                "mitigation": "key-only auth, fail2ban, source-IP allowlist",
            }]
        for tech in self.web_technologies:
            key = f"web:{tech['server']}:{tech['port']}"
            graph[key] = [{
                "threat": "web application surface (injection, auth bypass, RCE)",
                "impact": "data access or host compromise",
                "likelihood": "depends on app",
                "mitigation": "patch, WAF, input validation",
            }]
        if 3306 in self.open_ports:
            graph["mysql"] = [{
                "threat": "exposed database",
                "impact": "full DB read/write",
                "likelihood": "high if public",
                "mitigation": "bind to localhost, VPN, or allowlist",
            }]
        if 3389 in self.open_ports:
            graph["rdp"] = [{
                "threat": "remote desktop exposure",
                "impact": "interactive host access",
                "likelihood": "high — actively scanned",
                "mitigation": "VPN-gate, MFA, rate limit",
            }]
        self.threat_graph = graph
        return graph

    def risk_summary(self) -> dict[str, Any]:
        db_ports = {3306, 5432, 27017, 6379, 9200, 1433}
        mgmt_ports = {22, 3389, 5985, 5986}
        exposed_db = sorted(set(self.open_ports) & db_ports)
        exposed_mgmt = sorted(set(self.open_ports) & mgmt_ports)

        level = "low"
        if exposed_db:
            level = "high"
        elif len(self.vulnerabilities) >= 2 or (exposed_mgmt and len(self.open_ports) > 5):
            level = "medium"

        return {
            "overall_risk": level,
            "open_ports_count": len(self.open_ports),
            "vulnerability_count": len(self.vulnerabilities),
            "exposed_databases": exposed_db,
            "exposed_management": exposed_mgmt,
            "recommendation": "reduce attack surface; verify each exposed service is intended",
        }

    def generate_report(self) -> HostReport:
        return HostReport(
            timestamp=datetime.now(timezone.utc).isoformat(),
            target_ip=self.target_ip,
            hostname=self.hostname,
            geolocation=self.geolocation,
            open_ports=self.open_ports,
            services=[asdict(s) for s in self.services],
            web_technologies=self.web_technologies,
            vulnerabilities=[asdict(v) for v in self.vulnerabilities],
            dns_records=self.dns_records,
            ssl_certificate=self.ssl_certificate,
            threat_graph=self.threat_graph,
            crtsh_domains=self.crtsh_domains,
            risk_summary=self.risk_summary(),
            simulated=self.simulated,
        )

    def export_json(self, path: str) -> str:
        report = self.generate_report()
        with open(path, "w", encoding="utf-8") as f:
            json.dump(asdict(report), f, indent=2, default=str)
        log.info("report written: %s", path)
        return path

    def run_full_scan(self) -> HostReport:
        log.info("scanning %s", self.target_ip)
        self.resolve_hostname()
        self.query_shodan()
        self.query_ssl_certificate()
        self.query_crt_sh()
        self.build_threat_graph()
        return self.generate_report()


def _flatten_cert_name(name_seq: Any) -> dict[str, str]:
    out: dict[str, str] = {}
    for rdn in name_seq or []:
        for k, v in rdn:
            out[k] = v
    return out
