"""Unit and integration tests for STEALTHWALL block engine components."""

import json
import time
from pathlib import Path
import pytest

from block_engine.local_iptables import DryRunBlocker
from block_engine.asn_check import AsnCheck, AsnTable, ip_to_int
from block_engine.graduated_response import (
    GraduatedResponseEngine,
    OffenseHistory,
    Whitelist,
    Decision,
)
from block_engine.reconcile import ReconcileManager, FileSharedStore, BlockOp
from block_engine.cdn_integrations.cloudflare import CloudflarePusher, Account
from block_engine.captcha.mcaptcha import McaptchaProvider


def test_dry_run_blocker_lifecycle():
    blocker = DryRunBlocker()
    assert not blocker.request({"op": "check", "ip": "1.2.3.4"})["blocked"]

    # Apply block with 10s TTL
    res = blocker.block("1.2.3.4", ttl_seconds=10)
    assert res["ok"]
    assert blocker.request({"op": "check", "ip": "1.2.3.4"})["blocked"]
    assert len(blocker.blocks) == 1

    # Unblock
    unblock_res = blocker.unblock("1.2.3.4", reason="admin_unblock")
    assert unblock_res["ok"]
    assert not blocker.request({"op": "check", "ip": "1.2.3.4"})["blocked"]


def test_graduated_response_engine_tiers(tmp_path):
    blocker = DryRunBlocker()
    hist_file = tmp_path / "hist.json"
    wl_file = tmp_path / "wl.json"
    history = OffenseHistory(str(hist_file))
    whitelist = Whitelist(str(wl_file))

    # Dedicated ASN mock
    asn_mock = type("A", (), {
        "classify": staticmethod(lambda ip: {"is_shared_infra": False, "confidence_weight": 1.0, "asn": 12345}),
        "gating_available": staticmethod(lambda: True),
    })()

    engine = GraduatedResponseEngine(blocker, asn_gate=asn_mock, whitelist=whitelist, history=history)

    # 1. Low tier: score 0.40 -> log_only
    dec = engine.decide_and_respond("10.0.0.1", raw_score=0.40)
    assert dec.action == "log_only"
    assert dec.tier == "low"

    # 2. Medium tier: score 0.60 -> rate_limit
    dec = engine.decide_and_respond("10.0.0.2", raw_score=0.60)
    assert dec.action == "rate_limit"
    assert dec.tier == "medium"

    # 3. High tier: score 0.80 -> captcha
    captcha_mock = type("C", (), {"issue_challenge": staticmethod(lambda ip: {})})()
    engine.captcha_provider = captcha_mock
    dec = engine.decide_and_respond("10.0.0.3", raw_score=0.80)
    assert dec.action == "captcha"
    assert dec.tier == "high"

    # 4. Very High tier: score 0.95 -> temp_block (hours TTL)
    dec = engine.decide_and_respond("10.0.0.4", raw_score=0.95)
    assert dec.action == "temp_block"
    assert dec.tier == "very_high"
    assert 3600 <= dec.ttl_seconds <= 14400
    assert blocker.request({"op": "check", "ip": "10.0.0.4"})["blocked"]


def test_provisional_shared_ip_tier(tmp_path):
    blocker = DryRunBlocker()
    history = OffenseHistory(str(tmp_path / "hist.json"))
    whitelist = Whitelist(str(tmp_path / "wl.json"))

    # Shared infra mock (CGNAT / Cloud / Proxy)
    asn_shared = type("A", (), {
        "classify": staticmethod(lambda ip: {"is_shared_infra": True, "confidence_weight": 0.5, "asn": 13335}),
        "gating_available": staticmethod(lambda: True),
    })()

    engine = GraduatedResponseEngine(blocker, asn_gate=asn_shared, whitelist=whitelist, history=history)

    # High score on shared IP gets provisional short-TTL block (15-30 min)
    dec = engine.decide_and_respond("198.51.100.1", raw_score=0.65)
    assert dec.action == "provisional_block"
    assert dec.tier == "medium_shared"
    assert 900 <= dec.ttl_seconds <= 1800


def test_repeat_offender_escalation_and_decay(tmp_path):
    history = OffenseHistory(str(tmp_path / "hist.json"))
    ip = "192.0.2.55"
    now = 1000000.0

    assert history.effective_offenses(ip, now=now) == 0

    # Record 3 blocks
    history.record_block(ip, now=now)
    history.record_block(ip, now=now + 10)
    history.record_block(ip, now=now + 20)

    assert history.total_blocks(ip) == 3
    assert history.effective_offenses(ip, now=now + 20) >= 2

    # Long-term decay (after multiple half-lives)
    future = now + (365 * 86400)
    assert history.effective_offenses(ip, now=future) == 0


def test_whitelist_reauth_gate(tmp_path):
    wl = Whitelist(str(tmp_path / "whitelist.json"))
    ip = "192.168.1.100"

    # Reject if reauth is older than max allowed age (e.g., 300s) -> raises PermissionError
    with pytest.raises(PermissionError):
        wl.add(ip, actor="admin", reauth_age_seconds=600.0)
    assert not wl.contains(ip)

    # Accept with fresh reauth
    res_fresh = wl.add(ip, actor="admin", reauth_age_seconds=15.0)
    assert res_fresh["ok"]
    assert wl.contains(ip)

    # Remove with fresh reauth
    res_remove = wl.remove(ip, actor="admin", reauth_age_seconds=5.0)
    assert res_remove["ok"]
    assert not wl.contains(ip)


def test_asn_check_table_and_fail_loud():
    asn = AsnCheck(start_scheduler=False)
    assert ip_to_int("1.1.1.1") == 16843009
    assert ip_to_int("999.1.1.1") is None

    # Load custom TSV sample
    sample_tsv = (
        "16843008\t16843263\t13335\tUS\tCloudflare Inc\n"
        "167772160\t184549375\t16509\tUS\tAmazon.com, Inc.\n"
    )
    table = AsnTable()
    table.load_tsv(sample_tsv)
    rec = table.lookup(ip_to_int("1.1.1.1"))
    assert rec is not None
    assert rec.asn == 13335
    assert rec.is_shared_infra is True

    # Test failure counter escalation
    asn.consecutive_failures = 5
    assert not asn.gating_available()
    assert asn.state == asn.STATE_DEGRADED


def test_reconcile_manager_clock_skew_and_sync(tmp_path):
    store = FileSharedStore(str(tmp_path / "shared_store.json"))
    journal = tmp_path / "reconcile_journal.jsonl"
    reject_log = tmp_path / "reconcile_rejects.jsonl"

    mgr = ReconcileManager(
        store=store,
        pending_path=str(journal),
        reject_log_path=str(reject_log),
    )

    now = time.time()

    # Reject writes with clock skew > 300s (e.g. 1000s in the future)
    future_op = BlockOp(op="block", ip="10.1.1.1", ts=now + 1000.0, actor="rogue")
    mgr.record_pending(future_op)
    report = mgr.on_reconnect()
    assert len(report["rejected"]) == 1
    assert report["rejected"][0]["ip"] == "10.1.1.1"

    # Accept valid op
    valid_op = BlockOp(op="block", ip="10.1.1.2", ts=now - 10.0, actor="local_admin", ttl_seconds=3600)
    mgr.record_pending(valid_op)
    report2 = mgr.on_reconnect()
    assert len(report2["applied"]) == 1
    assert store.fetch("10.1.1.2") is not None


def test_cloudflare_pusher_dry_run():
    acc = Account({"name": "test_acc", "zone_id": "z123", "api_token": "tok"})
    pusher = CloudflarePusher(accounts=[acc], dry_run=True)
    res = pusher.push_block("203.0.113.1", reason="test_scan")
    assert res is True
    status = pusher.sync_status()
    assert "test_acc" in status
    pusher.stop()


def test_mcaptcha_provider_dry_run():
    provider = McaptchaProvider()
    assert not provider.available
