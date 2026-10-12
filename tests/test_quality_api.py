def test_quality_score_contract(client):
    response = client.post("/api/v1/quality/score", json={
        "latencyMs": 35, "jitterMs": 6, "downloadMbps": 120, "uploadMbps": 20, "contractedMbps": 200})

    body = response.json()
    assert response.status_code == 200
    assert 0 <= body["score"] <= 100
    assert body["grade"] in ("EXCELLENT", "GOOD", "FAIR", "POOR")
    assert body["gradeLabel"]
    assert body["contractedRatio"] == 0.6
    assert {m["metric"] for m in body["metrics"]} == {"latency", "jitter", "download", "upload"}
    assert body["modelVersion"] == "quality-1.0"


def test_quality_score_validates_ranges(client):
    response = client.post("/api/v1/quality/score", json={"latencyMs": -1, "jitterMs": 3})

    assert response.status_code == 422


def test_quality_score_requires_api_key(client):
    response = client.post("/api/v1/quality/score", headers={"X-API-Key": "wrong"},
                           json={"latencyMs": 20, "jitterMs": 3})

    assert response.status_code == 401
