"""Unit tests for Webhook Notifier & Alerting."""

import time
import pytest
from block_engine.alerting import WebhookNotifier


def test_webhook_notifier_dispatch_and_debounce():
    # Without a configured URL, dispatch safely returns False
    notifier = WebhookNotifier(webhook_url="")
    assert not notifier.dispatch({"ip": "1.2.3.4", "action": "block"})

    # With dummy URL, enqueues successfully
    notifier_active = WebhookNotifier(webhook_url="http://localhost:9999/webhook")
    incident = {"ip": "198.51.100.4", "action": "block", "tier": "very_high", "raw_score": 0.95}

    res1 = notifier_active.dispatch(incident)
    assert res1 is True

    # Debounce: rapid immediate subsequent alert on same IP is debounced
    res2 = notifier_active.dispatch(incident)
    assert res2 is False

    notifier_active.stop()
