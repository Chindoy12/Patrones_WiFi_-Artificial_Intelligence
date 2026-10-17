def test_channel_recommend_contract(client):
    response = client.post("/api/v1/channel/recommend", json={
        "band": "2.4", "channel": 6,
        "channelCounts": [{"channel": 1, "networks": 3}, {"channel": 6, "networks": 4}]})

    body = response.json()
    assert response.status_code == 200
    assert body["shouldChange"] is True
    assert body["currentChannel"] == 6
    assert body["recommendedChannel"] == 11
    assert body["options"][0] == {"channel": 1, "networks": 3, "load": 3.0}
    assert body["modelVersion"] == "channel-1.0"


def test_channel_recommend_rejects_invalid_values(client):
    assert client.post("/api/v1/channel/recommend", json={"band": "3"}).status_code == 422
    assert client.post("/api/v1/channel/recommend", json={"channelCounts": [{"channel": 0, "networks": 1}]}
                       ).status_code == 422


def test_channel_recommend_requires_api_key(client):
    assert client.post("/api/v1/channel/recommend", headers={"X-API-Key": "wrong"}, json={}).status_code == 401
