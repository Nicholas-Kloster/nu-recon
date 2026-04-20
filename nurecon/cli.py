"""CLI entrypoint for nu-recon."""
from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import sys
from dataclasses import asdict

from .mapper import TargetedHostMapper


def _valid_ip(value: str) -> str:
    try:
        ipaddress.ip_address(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid IP: {value}") from exc
    return value


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="nu-recon",
        description="Targeted single-host passive recon.",
    )
    p.add_argument("target", type=_valid_ip, help="target IP address")
    p.add_argument("-o", "--output", default="host-report.json", help="output JSON path")
    p.add_argument("--shodan-key", default=None, help="Shodan API key (else SHODAN_API_KEY env)")
    p.add_argument("--ssl-port", type=int, default=443, help="TLS port for cert grab")
    p.add_argument("--crtsh-identity", default=None, help="domain to query crt.sh (overrides PTR)")
    p.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    p.add_argument("--no-network", action="store_true", help="skip all network calls (for testing)")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )

    mapper = TargetedHostMapper(args.target, shodan_api_key=args.shodan_key)

    if args.no_network:
        mapper.simulated = True
        mapper._load_simulated_shodan()
        mapper.build_threat_graph()
    else:
        mapper.resolve_hostname()
        mapper.query_shodan()
        mapper.query_ssl_certificate(port=args.ssl_port)
        mapper.query_crt_sh(identity=args.crtsh_identity)
        mapper.build_threat_graph()

    path = mapper.export_json(args.output)
    report = mapper.generate_report()
    print(json.dumps(asdict(report), indent=2, default=str))
    print(f"\n[+] report: {path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
