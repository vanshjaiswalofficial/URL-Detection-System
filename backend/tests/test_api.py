"""API contract and endpoint integration tests for PhishGuard AI (TASKS T4.1, T4.2)."""

from __future__ import annotations

from fastapi.testclient import TestClient

from backend.app.main import app

client = TestClient(app)


def test_health() -> None:
    res = client.get("/v1/health")
    assert res.status_code == 200
    assert res.json() == {"status": "ok"}


def test_ready_and_model_info() -> None:
    res = client.get("/v1/ready")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ready"
    assert "model_version" in data

    info_res = client.get("/v1/model/info")
    assert info_res.status_code == 200
    info_data = info_res.json()
    assert "thresholds" in info_data
    assert info_data["features_count"] >= 30


def test_scan_benign_url() -> None:
    payload = {"url": "https://www.google.com/search?q=test"}
    res = client.post("/v1/scan", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["verdict"] == "no_threat_found"
    assert data["risk_score"] == 0
    assert data["layers"]["allowlist"] == "hit"
    assert "latency_ms" in data


def test_scan_phishing_url() -> None:
    payload = {"url": "https://paypal.com.verify-account.update-service.cc/signin"}
    res = client.post("/v1/scan", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["verdict"] == "malicious"
    assert data["risk_score"] >= 70
    assert len(data["reasons"]) >= 1


def test_scan_oversize_url_rejected() -> None:
    """RULES R-SEC-2: URL > 2048 characters must be rejected."""
    long_url = "https://example.com/" + ("a" * 2050)
    payload = {"url": long_url}
    res = client.post("/v1/scan", json=payload)
    assert res.status_code == 422  # Pydantic validation error


def test_scan_batch() -> None:
    urls = [
        "https://www.google.com",
        "http://paypa1-support.com/login",
        "https://wikipedia.org/wiki/Phishing",
    ]
    res = client.post("/v1/scan/batch", json={"urls": urls})
    assert res.status_code == 200
    data = res.json()
    assert data["count"] == 3
    assert len(data["results"]) == 3


def test_feedback() -> None:
    valid_payload = {
        "scan_id": "test-id-123",
        "url_canonical_hash": "dummyhash",
        "feedback_label": "false_positive",
    }
    res = client.post("/v1/feedback", json=valid_payload)
    assert res.status_code == 201
    assert res.json()["status"] == "recorded"

    invalid_payload = {
        "scan_id": "test-id-123",
        "url_canonical_hash": "dummyhash",
        "feedback_label": "invalid_label_value",
    }
    res2 = client.post("/v1/feedback", json=invalid_payload)
    assert res2.status_code == 422
    assert "application/problem+json" in res2.headers.get("content-type", "")
    data2 = res2.json()
    assert "status" in data2
    assert "detail" in data2
    assert "title" in data2


def test_user_lists_isolation_and_multitenant_rejection() -> None:
    """TASKS T4.4: Multi-tenant hosts rejected from allowlist; user allow only affects that key."""
    # 1. Multi-tenant host rejection from allowlist
    mt_res = client.post("/v1/lists", json={
        "user_key": "user_alice",
        "list_type": "allow",
        "entry": "github.io",
    })
    assert mt_res.status_code == 400
    assert "multi-tenant" in mt_res.json()["detail"]

    # 2. Add custom allow for user_alice
    custom_domain = "my-internal-corp-tool.xyz"
    add_res = client.post("/v1/lists", json={
        "user_key": "user_alice",
        "list_type": "allow",
        "entry": custom_domain,
    })
    assert add_res.status_code == 201

    # 3. Scanning with user_alice key hits user allowlist
    scan_alice = client.post("/v1/scan", json={
        "url": f"https://{custom_domain}/dashboard",
        "user_key": "user_alice",
    })
    assert scan_alice.status_code == 200
    assert scan_alice.json()["verdict"] == "no_threat_found"
    assert scan_alice.json()["layers"]["user_list"] == "allow_hit"

    # 4. Scanning with user_bob does NOT hit user_alice's allowlist (user isolation)
    scan_bob = client.post("/v1/scan", json={
        "url": f"https://{custom_domain}/dashboard",
        "user_key": "user_bob",
    })
    assert scan_bob.status_code == 200
    assert scan_bob.json()["layers"]["user_list"] != "allow_hit"

    # 5. User denylist hits
    client.post("/v1/lists", json={
        "user_key": "user_alice",
        "list_type": "deny",
        "entry": "blocked-for-alice.com",
    })
    scan_deny = client.post("/v1/scan", json={
        "url": "https://blocked-for-alice.com/test",
        "user_key": "user_alice",
    })
    assert scan_deny.status_code == 200
    assert scan_deny.json()["verdict"] == "malicious"
    assert scan_deny.json()["layers"]["user_list"] == "deny_hit"

    # 6. Retrieve user lists
    get_res = client.get("/v1/lists?user_key=user_alice")
    assert get_res.status_code == 200
    lists_data = get_res.json()
    assert custom_domain in lists_data["allow"]
    assert "blocked-for-alice.com" in lists_data["deny"]

    # 7. Delete entry
    del_res = client.delete(f"/v1/lists?user_key=user_alice&list_type=allow&entry={custom_domain}")
    assert del_res.status_code == 200

