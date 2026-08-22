"""Unit tests for Edge Sync Manager (Cloudflare & AWS WAF)."""

import pytest
from block_engine.cdn_integrations.edge_sync import EdgeSyncManager


def test_edge_sync_manager_dry_run_queueing():
    mgr = EdgeSyncManager(dry_run=True)
    res_b = mgr.sync_block("203.0.113.8", ttl_seconds=1800, reason="test_scan")
    assert res_b is True

    res_u = mgr.sync_unblock("203.0.113.8")
    assert res_u is True

    status = mgr.status()
    assert status["dry_run"] is True
    assert "providers" in status

    mgr.stop()
