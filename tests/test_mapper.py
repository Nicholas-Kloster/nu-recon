"""Unit tests for nu-recon — no network calls."""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from nurecon.mapper import TargetedHostMapper


SHODAN_SAMPLE = {
    "ports": [443, 22, 80],
    "hostnames": ["example.test"],
    "country_name": "Germany",
    "city": "Munich",
    "org": "TestCorp",
    "isp": "TestISP",
    "data": [
        {"port": 22, "product": "OpenSSH", "version": "8.9p1", "data": "SSH-2.0-OpenSSH_8.9"},
        {"port": 80, "product": "nginx", "version": "1.24.0", "data": "HTTP/1.1 200 OK"},
        {"port": 443, "product": "nginx", "version": "1.24.0", "data": "HTTP/1.1 200 OK"},
    ],
}


def make_mapper(key: str | None = None) -> TargetedHostMapper:
    session = MagicMock()
    return TargetedHostMapper("192.0.2.10", shodan_api_key=key, http_session=session)


def test_simulated_mode_when_no_key():
    m = make_mapper(key=None)
    m.query_shodan()
    assert m.simulated is True
    assert 22 in m.open_ports
    assert any(s.version == "(simulated)" for s in m.services)


def test_shodan_real_path_ingests_data():
    m = make_mapper(key="fake-key")
    resp = MagicMock(status_code=200)
    resp.json.return_value = SHODAN_SAMPLE
    m.http.get.return_value = resp

    assert m.query_shodan() is True
    assert m.open_ports == [22, 80, 443]
    assert m.hostname == "example.test"
    assert m.geolocation["org"] == "TestCorp"
    assert any(t["server"] == "nginx" for t in m.web_technologies)
    assert m.simulated is False


def test_shodan_non_200_returns_false():
    m = make_mapper(key="fake-key")
    resp = MagicMock(status_code=403, text="forbidden")
    m.http.get.return_value = resp
    assert m.query_shodan() is False


def test_crtsh_skipped_without_hostname():
    m = make_mapper(key="k")
    m.hostname = None
    assert m.query_crt_sh() == []
    m.http.get.assert_not_called()


def test_crtsh_parses_response():
    m = make_mapper(key="k")
    m.hostname = "example.test"
    resp = MagicMock(status_code=200)
    resp.json.return_value = [
        {"name_value": "example.test\n*.example.test"},
        {"name_value": "mail.example.test"},
    ]
    m.http.get.return_value = resp

    out = m.query_crt_sh()
    assert "example.test" in out
    assert "mail.example.test" in out
    assert all(not d.startswith("*.") for d in out)


def test_threat_graph_flags_db_and_mgmt():
    m = make_mapper()
    m.open_ports = [22, 3306, 80]
    m.web_technologies = [{"port": 80, "server": "nginx", "version": "1.24"}]
    graph = m.build_threat_graph()
    assert "ssh" in graph
    assert "mysql" in graph
    assert any(k.startswith("web:nginx") for k in graph)


def test_risk_summary_high_when_db_exposed():
    m = make_mapper()
    m.open_ports = [22, 5432]
    summary = m.risk_summary()
    assert summary["overall_risk"] == "high"
    assert 5432 in summary["exposed_databases"]


def test_risk_summary_low_when_minimal():
    m = make_mapper()
    m.open_ports = [443]
    assert m.risk_summary()["overall_risk"] == "low"


def test_export_json_roundtrip(tmp_path):
    m = make_mapper()
    m.open_ports = [443]
    m.build_threat_graph()
    out = tmp_path / "r.json"
    m.export_json(str(out))
    data = json.loads(out.read_text())
    assert data["target_ip"] == "192.0.2.10"
    assert data["risk_summary"]["overall_risk"] == "low"
    assert "timestamp" in data


def test_cli_rejects_invalid_ip():
    from nurecon.cli import build_parser
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["not-an-ip"])


def test_cli_no_network_mode(tmp_path):
    from nurecon.cli import main
    out = tmp_path / "r.json"
    rc = main(["192.0.2.10", "-o", str(out), "--no-network"])
    assert rc == 0
    data = json.loads(out.read_text())
    assert data["simulated"] is True
    assert data["target_ip"] == "192.0.2.10"
