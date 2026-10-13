"""GET /api/v1/model/evaluation: the comparison computed in the background at startup."""

def test_model_evaluation_compares_three_algorithms(client):
    assert client.app.state.evaluation.wait(timeout=180)

    body = client.get("/api/v1/model/evaluation").json()

    assert [a["algorithm"] for a in body["algorithms"]] == ["IsolationForest", "LocalOutlierFactor", "OneClassSVM"]
    assert [a["algorithm"] for a in body["algorithms"] if a["production"]] == ["IsolationForest"]
    assert 0 < body["diagnosis"]["accuracy"] <= 1
    assert "sintéticos" in body["dataset"]


def test_model_evaluation_requires_api_key(client):
    response = client.get("/api/v1/model/evaluation", headers={"X-API-Key": "wrong"})

    assert response.status_code == 401
