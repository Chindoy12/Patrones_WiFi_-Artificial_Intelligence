def test_security_assess_contract(client):
    response = client.post("/api/v1/security/assess", json={
        "authentication": "WPA2", "cipher": "CCMP", "openPorts": [23, 80], "deviceCount": 8, "newDeviceCount": 1,
        "band": "5", "channel": 36, "neighborsSameChannel": 1})

    body = response.json()
    assert response.status_code == 200
    assert body["grade"] == "AT_RISK"
    assert body["gradeLabel"] == "En riesgo"
    assert [f["code"] for f in body["findings"]] == ["PORT_TELNET", "ADMIN_HTTP", "NEW_DEVICES"]
    assert body["findings"][0]["severity"] == "HIGH"
    assert body["modelVersion"] == "security-1.0"


def test_security_assess_rejects_unknown_values(client):
    assert client.post("/api/v1/security/assess", json={"authentication": "SUPER"}).status_code == 422
    assert client.post("/api/v1/security/assess", json={"openPorts": [70000]}).status_code == 422


def test_security_assess_requires_api_key(client):
    response = client.post("/api/v1/security/assess", headers={"X-API-Key": "wrong"}, json={})

    assert response.status_code == 401
