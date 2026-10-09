from tests.conftest import DEGRADED, NORMAL


def test_health_is_public(client):
    response = client.get("/health", headers={"X-API-Key": ""})

    assert response.status_code == 200


def test_detect_requires_api_key(client):
    response = client.post("/api/v1/anomalies/detect", headers={"X-API-Key": "wrong"},
                           json={"networkId": 1, "simulatedData": True, "measurements": [NORMAL]})

    assert response.status_code == 401


def test_detect_returns_camel_case_contract(client):
    response = client.post("/api/v1/anomalies/detect",
                           json={"networkId": 1, "simulatedData": True, "measurements": [NORMAL, DEGRADED]})

    body = response.json()
    assert response.status_code == 200
    assert body["anomalyDetected"] is True
    assert body["simulatedData"] is True
    assert {"anomalyScore", "severity", "message", "contributingFeatures", "modelVersion"} <= body.keys()


def test_detect_rejects_invalid_measurements(client):
    response = client.post("/api/v1/anomalies/detect",
                           json={"networkId": 1, "simulatedData": True, "measurements": [{**NORMAL, "packetLoss": 140}]})

    assert response.status_code == 422


def test_detect_rejects_empty_window(client):
    response = client.post("/api/v1/anomalies/detect", json={"networkId": 1, "simulatedData": True, "measurements": []})

    assert response.status_code == 422


def test_model_info(client):
    body = client.get("/api/v1/model").json()

    assert body["algorithm"] == "IsolationForest"
    assert len(body["features"]) == 8
