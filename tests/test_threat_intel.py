"""Unit tests for Threat Intelligence and GeoIP resolver."""

import pytest
from block_engine.threat_intel import ThreatIntelResolver


def test_threat_intel_local_loopback():
    resolver = ThreatIntelResolver()
    res = resolver.resolve("127.0.0.1")
    assert res["country"] == "LOCAL"
    assert res["is_tor"] is False
    assert res["threat_level"] == "none"

    res_priv = resolver.resolve("192.168.1.50")
    assert res_priv["country"] == "LOCAL"


def test_threat_intel_tor_detection():
    resolver = ThreatIntelResolver(tor_nodes={"185.220.101.5"})
    res = resolver.resolve("185.220.101.5")
    assert res["is_tor"] is True
    assert res["threat_level"] == "high"


def test_threat_intel_caching_and_dynamic_nodes():
    resolver = ThreatIntelResolver()
    ip = "203.0.113.199"
    res1 = resolver.resolve(ip)
    assert res1["is_tor"] is False

    # Dynamically add to Tor list
    resolver.add_tor_node(ip)
    res2 = resolver.resolve(ip)
    assert res2["is_tor"] is True
