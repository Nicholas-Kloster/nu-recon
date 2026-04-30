[![Claude Code Friendly](https://img.shields.io/badge/Claude_Code-Friendly-blueviolet?logo=anthropic&logoColor=white)](https://claude.ai/code)

# nu-recon

Targeted single-host passive reconnaissance. Given one IPv4, produce a JSON
report covering reverse DNS, Shodan host lookup, TLS certificate details,
crt.sh certificate transparency results, and a small threat graph + risk
summary.

Built for authorized security assessments and disclosure-oriented research.
The tool performs lookups against third-party services (Shodan, crt.sh) and
opens a single TLS socket to the target for certificate retrieval — nothing
more. No brute forcing, no exploitation, no active scanning.

## Install

```bash
pip install -r requirements.txt
# or editable:
pip install -e .
```

## Usage

```bash
export SHODAN_API_KEY=...          # optional; without it, simulated data is used
nu-recon 192.0.2.10 -o report.json
nu-recon 192.0.2.10 --ssl-port 8443 --crtsh-identity example.test
nu-recon 192.0.2.10 --no-network   # offline smoke run
```

CLI flags:

| flag | purpose |
|---|---|
| `target` | IPv4 address (required, validated) |
| `-o/--output` | output JSON path (default `host-report.json`) |
| `--shodan-key` | override env var |
| `--ssl-port` | TLS port for certificate retrieval (default 443) |
| `--crtsh-identity` | domain to query on crt.sh (overrides PTR) |
| `-v/--verbose` | debug logging |
| `--no-network` | skip all network I/O (for tests / dry runs) |

## Report fields

- `target_ip`, `hostname`, `geolocation`
- `open_ports`, `services`, `web_technologies`
- `ssl_certificate` (subject, issuer, SANs, validity window)
- `crtsh_domains` (certificate transparency associations)
- `threat_graph` — per-service threat/impact/mitigation entries
- `risk_summary` — low/medium/high based on exposed DB / management ports
- `simulated` — `true` when Shodan data was substituted with placeholder values

## Tests

```bash
pip install -r requirements-dev.txt
pytest
```

## Authorization

This tool is intended for use against assets you own or are explicitly
authorized to test. Passive lookups still generate log entries at Shodan and
crt.sh; TLS certificate retrieval creates a connection to the target. Use
accordingly.
