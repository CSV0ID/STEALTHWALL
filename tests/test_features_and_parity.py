"""Unit tests for feature extraction and scoring pipeline."""

import math
import pytest
from middleware.fastapi.stealthwall_fastapi.features import (
    extract_features,
    normalize_path,
    shannon_entropy,
    byte_entropy,
    population_variance,
    round_to,
    matches_signature,
)
from middleware.fastapi.stealthwall_fastapi.scoring import ScoringPipeline, signature_capped


def test_normalize_path_spec_v1():
    # 1. Query string stripped
    assert normalize_path("/index.html?user=admin&debug=1") == "/index.html"

    # 2. Digit runs replaced by 'N'
    assert normalize_path("/user/12345/profile/99") == "/user/Nprofile/N"

    # 3. Slashes collapsed
    assert normalize_path("///api///v1///test//") == "/api/vN/test"

    # 4. Trailing slash stripped
    assert normalize_path("/admin/") == "/admin"
    assert normalize_path("/") == "/"

    # 5. ASCII uppercase lowercased, non-ASCII preserved
    assert normalize_path("/API/Admin/Über") == "/api/admin/Über"


def test_shannon_and_byte_entropy():
    # Empty or single-item
    assert shannon_entropy([]) == 0.0
    assert shannon_entropy(["a"]) == 0.0

    # 2 distinct items equal probability: - (0.5 * log2(0.5) + 0.5 * log2(0.5)) = 1.0
    assert shannon_entropy(["a", "b"]) == 1.0

    # Byte entropy
    assert byte_entropy("") == 0.0
    assert byte_entropy("AAAA") == 0.0


def test_population_variance_and_round_to():
    assert population_variance([]) == 0.0
    assert population_variance([5.0]) == 0.0
    assert population_variance([2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0]) == 4.0

    # Half-up rounding
    assert round_to(0.1234567) == 0.123457
    assert round_to(0.1234564) == 0.123456


def test_matches_signature():
    path = "/search?q=union+select+1,2,3"
    payload = "<script>alert(1)</script>"
    assert matches_signature(path, payload) is True
    assert matches_signature("/normal/page", "hello world") is False


def test_signature_capped_scoring():
    # Model that outputs high score only when signature is present
    def mock_model(vec):
        sig_val = vec[6]
        # if signature is high, return 0.90, else 0.10
        return 0.90 if sig_val > 0.0 else 0.10

    vec_with_sig = [0.1, 0.1, 0.1, 0.0, 0.0, 0.0, 1.0, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]
    final, raw = signature_capped(mock_model, vec_with_sig)
    assert raw == 0.90
    # Signature alone can never drive score above neutral / (1 - cap) = 0.10 / 0.70 ~= 0.1428
    assert final <= 0.15, f"Signature alone should be heavily capped, got {final}"


def test_extract_features_window_behavior():
    events = [{
        "ts": 100.0,
        "method": "GET",
        "path": "/page1",
        "status": 200,
        "payload": "",
        "headers": {"user-agent": "test"},
        "user_agent": "test",
        "is_auth_failure": False,
    }]

    vec = extract_features(events)
    assert vec is not None
    assert len(vec) == 14
    assert vec[0] > 0.0  # request rate
