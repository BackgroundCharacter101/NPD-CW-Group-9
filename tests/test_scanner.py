#!/usr/bin/env python3
"""
tests/test_scanner.py — Unit tests for scanner.py
Covers all five project phases without requiring a live network.

Run with:
    python -m pytest tests/ -v
    python -m pytest tests/ -v --tb=short
"""

import sys
import os
import json
import csv
import tempfile
import argparse

# Make parent directory importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
import scanner as sc


# ─────────────────────────────────────────────────────────────────────────────
#  PHASE 1 — Core Networking Layer
# ─────────────────────────────────────────────────────────────────────────────

class TestServiceFingerprinting:
    """Phase 1 — service map and get_service()."""

    def test_known_ports(self):
        assert sc.get_service(22)   == "SSH"
        assert sc.get_service(80)   == "HTTP"
        assert sc.get_service(443)  == "HTTPS"
        assert sc.get_service(3306) == "MySQL"
        assert sc.get_service(5432) == "PostgreSQL"
        assert sc.get_service(6379) == "Redis"
        assert sc.get_service(27017)== "MongoDB"

    def test_unknown_port(self):
        assert sc.get_service(65001) == "Unknown"
        assert sc.get_service(1)     == "Unknown"

    def test_all_map_entries_are_strings(self):
        for port, svc in sc.COMMON_SERVICES.items():
            assert isinstance(port, int)
            assert isinstance(svc, str) and len(svc) > 0

    def test_map_has_minimum_entries(self):
        assert len(sc.COMMON_SERVICES) >= 50


class TestPortParsing:
    """Phase 1/2 — parse_ports()."""

    def test_single_port(self):
        assert sc.parse_ports("80") == [80]

    def test_port_range(self):
        result = sc.parse_ports("1-5")
        assert result == [1, 2, 3, 4, 5]

    def test_comma_list(self):
        assert sc.parse_ports("22,80,443") == [22, 80, 443]

    def test_mixed(self):
        result = sc.parse_ports("22,80,8000-8002")
        assert result == [22, 80, 8000, 8001, 8002]

    def test_deduplication(self):
        result = sc.parse_ports("80,80,80")
        assert result == [80]

    def test_sorted_output(self):
        result = sc.parse_ports("443,22,80")
        assert result == [22, 80, 443]

    def test_invalid_port_string(self):
        with pytest.raises(argparse.ArgumentTypeError):
            sc.parse_ports("abc")

    def test_out_of_range_port(self):
        with pytest.raises(argparse.ArgumentTypeError):
            sc.parse_ports("0")
        with pytest.raises(argparse.ArgumentTypeError):
            sc.parse_ports("65536")

    def test_empty_string(self):
        with pytest.raises(argparse.ArgumentTypeError):
            sc.parse_ports("")


class TestResolveTargets:
    """Phase 2 — resolve_targets()."""

    def test_single_ip(self):
        result = sc.resolve_targets("127.0.0.1")
        assert result == ["127.0.0.1"]

    def test_cidr_24(self):
        result = sc.resolve_targets("192.168.1.0/30")
        # /30 gives 2 usable host IPs
        assert len(result) == 2
        assert "192.168.1.1" in result
        assert "192.168.1.2" in result

    def test_cidr_32(self):
        result = sc.resolve_targets("10.0.0.1/32")
        assert result == ["10.0.0.1"]

    def test_invalid_target(self):
        with pytest.raises(ValueError):
            sc.resolve_targets("not.a.real.host.xyzzy12345")

    def test_is_valid_ip(self):
        assert sc._is_valid_ip("192.168.1.1") is True
        assert sc._is_valid_ip("255.255.255.255") is True
        assert sc._is_valid_ip("not-an-ip") is False
        assert sc._is_valid_ip("") is False


# ─────────────────────────────────────────────────────────────────────────────
#  PHASE 4 — OS Fingerprinting & Ping Sweep
# ─────────────────────────────────────────────────────────────────────────────

class TestOsHint:
    """Phase 4 — os_hint_from_ttl()."""

    def test_linux(self):
        assert "Linux" in sc.os_hint_from_ttl(64)
        assert "Linux" in sc.os_hint_from_ttl(54)   # after 10 hops

    def test_windows(self):
        assert "Windows" in sc.os_hint_from_ttl(128)
        assert "Windows" in sc.os_hint_from_ttl(120)

    def test_network_device(self):
        assert "Cisco" in sc.os_hint_from_ttl(255)
        assert "Cisco" in sc.os_hint_from_ttl(200)

    def test_zero_ttl(self):
        assert sc.os_hint_from_ttl(0) == "Unknown"


class TestTopPorts:
    """Phase 4 — TOP_100_PORTS list."""

    def test_is_sorted(self):
        assert sc.TOP_100_PORTS == sorted(sc.TOP_100_PORTS)

    def test_no_duplicates(self):
        assert len(sc.TOP_100_PORTS) == len(set(sc.TOP_100_PORTS))

    def test_contains_common_ports(self):
        for p in (22, 80, 443, 3306, 5432):
            assert p in sc.TOP_100_PORTS

    def test_valid_range(self):
        for p in sc.TOP_100_PORTS:
            assert 1 <= p <= 65535


# ─────────────────────────────────────────────────────────────────────────────
#  PHASE 5 — Export & Logging
# ─────────────────────────────────────────────────────────────────────────────

SAMPLE_RESULTS = [
    {
        "host": "192.168.1.1",
        "open_ports": [
            {"port": 22,  "service": "SSH",   "banner": "SSH-2.0-Test"},
            {"port": 80,  "service": "HTTP",  "banner": "HTTP/1.1 200 OK"},
        ],
        "total_scanned": 1024,
        "elapsed_seconds": 3.5,
        "timestamp": "2026-05-03T10:00:00",
    }
]


class TestExportJson:
    """Phase 5 — export_json()."""

    def test_creates_file(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            sc.export_json(SAMPLE_RESULTS, path)
            assert os.path.isfile(path)
        finally:
            os.unlink(path)

    def test_json_structure(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            path = f.name
        try:
            sc.export_json(SAMPLE_RESULTS, path)
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            assert "tool" in data
            assert "results" in data
            assert data["total_hosts"] == 1
            assert data["results"][0]["host"] == "192.168.1.1"
        finally:
            os.unlink(path)


class TestExportCsv:
    """Phase 5 — export_csv()."""

    def test_creates_file(self):
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            path = f.name
        try:
            sc.export_csv(SAMPLE_RESULTS, path)
            assert os.path.isfile(path)
        finally:
            os.unlink(path)

    def test_csv_rows(self):
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False, mode="w") as f:
            path = f.name
        try:
            sc.export_csv(SAMPLE_RESULTS, path)
            with open(path, newline="", encoding="utf-8") as f:
                rows = list(csv.DictReader(f))
            # 2 open ports → 2 rows
            assert len(rows) == 2
            assert rows[0]["host"] == "192.168.1.1"
            assert rows[0]["port"] == "22"
            assert rows[1]["port"] == "80"
        finally:
            os.unlink(path)


class TestSetupLogging:
    """Phase 5 — setup_logging()."""

    def test_logger_created(self):
        with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as f:
            path = f.name
        try:
            logger = sc.setup_logging(path)
            logger.info("test message")
            # Close all handlers so Windows releases the file lock
            for h in logger.handlers[:]:
                h.close()
                logger.removeHandler(h)
            with open(path, encoding="utf-8") as f:
                content = f.read()
            assert "test message" in content
        finally:
            os.unlink(path)


class TestCLIParser:
    """Phase 3/5 — build_parser() argument validation."""

    def setup_method(self):
        self.parser = sc.build_parser()

    def test_required_target(self):
        with pytest.raises(SystemExit):
            self.parser.parse_args([])

    def test_defaults(self):
        args = self.parser.parse_args(["-t", "192.168.1.1"])
        assert args.ports    == "1-1024"
        assert args.threads  == 100
        assert args.timeout  == 1.0
        assert args.no_banner is False
        assert args.quiet    is False
        assert args.top_ports is False
        assert args.ping_sweep is False

    def test_top_ports_flag(self):
        args = self.parser.parse_args(["-t", "192.168.1.1", "--top-ports"])
        assert args.top_ports is True

    def test_ping_sweep_flag(self):
        args = self.parser.parse_args(["-t", "192.168.1.0/24", "--ping-sweep"])
        assert args.ping_sweep is True

    def test_output_flag(self):
        args = self.parser.parse_args(["-t", "10.0.0.1", "-o", "out.json"])
        assert args.output == "out.json"
