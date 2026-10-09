import pytest
from fastapi.testclient import TestClient

NORMAL = {"latency": 20, "jitter": 4, "packetLoss": 0.3, "bandwidth": 280, "signalStrength": -55,
          "trafficVolume": 200, "connectedDevices": 30, "packetCount": 170000}
DEGRADED = {"latency": 300, "jitter": 80, "packetLoss": 25, "bandwidth": 5, "signalStrength": -88,
            "trafficVolume": 200, "connectedDevices": 30, "packetCount": 170000}


@pytest.fixture(scope="session")
def client(tmp_path_factory, monkeypatch_session):
    monkeypatch_session.setattr("app.main.MODEL_PATH", str(tmp_path_factory.mktemp("model") / "model.joblib"))
    monkeypatch_session.setattr("app.main.API_KEY", "test-key")
    monkeypatch_session.delenv("ANTHROPIC_API_KEY", raising=False)
    from app.main import app
    with TestClient(app, headers={"X-API-Key": "test-key"}) as test_client:
        yield test_client


@pytest.fixture(scope="session")
def monkeypatch_session():
    with pytest.MonkeyPatch.context() as patch:
        yield patch
