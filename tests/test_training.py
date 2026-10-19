from datetime import datetime, timedelta, timezone

import numpy as np
import pytest

from app import training
from app.model_service import MODEL_VERSION, AnomalyDetectionService, generate_baseline
from app.schemas import TrainingMetrics, TrainingRequest


def real_samples(count: int = 600, seed: int = 7) -> list[dict]:
    """A home network slower than the synthetic baseline (about 45 ms) and without Wi-Fi signal (agent on cable)."""
    rng = np.random.default_rng(seed)
    start = datetime(2026, 10, 12, tzinfo=timezone.utc)
    return [{
        "latency": float(rng.lognormal(np.log(45), 0.3)),
        "jitter": float(rng.lognormal(np.log(6), 0.4)),
        "packetLoss": float(rng.uniform(0, 0.8)),
        "bandwidth": float(rng.normal(60, 8)),
        "connectedDevices": int(rng.integers(4, 12)),
        "trafficVolume": float(rng.lognormal(np.log(80), 0.4)),
        "packetCount": int(rng.lognormal(np.log(6000), 0.4)),
        "timestamp": (start + timedelta(minutes=5 * i)).isoformat(),
    } for i in range(count)]


@pytest.fixture(scope="module")
def synthetic() -> AnomalyDetectionService:
    return AnomalyDetectionService.train(generate_baseline())


def request(**overrides) -> TrainingRequest:
    return TrainingRequest.model_validate({"version": "real-20261019-1", "samples": real_samples(), **overrides})


def test_real_model_replaces_the_synthetic_one_when_it_gives_fewer_false_alarms(synthetic):
    result, model = training.train(request(), synthetic)

    assert result.decision == "PROMOTED" and result.active
    assert result.train_samples == 480 and result.test_normal == 120 and result.test_faults == 120
    assert result.candidate.false_positive_rate < result.current.false_positive_rate
    assert result.current_version == MODEL_VERSION
    assert model.version == "real-20261019-1" and model.samples == 600 and model.real_data
    assert "600 mediciones reales" in model.trained_on


def test_not_activated_when_only_evaluating(synthetic):
    result, model = training.train(request(activate=False), synthetic)

    assert result.decision == "PROMOTED" and not result.active and model is None


def test_restore_rebuilds_without_evaluating(synthetic):
    result, model = training.train(request(restore=True), synthetic)

    assert result.decision == "RESTORED" and result.candidate is None
    assert model.version == "real-20261019-1"


def test_restored_model_is_the_same_each_time(synthetic):
    _, first = training.train(request(restore=True), synthetic)
    _, second = training.train(request(restore=True), synthetic)
    probe = training.to_frame(request())
    assert (first.flag_raw(probe) == second.flag_raw(probe)).all()


def test_needs_enough_samples(synthetic):
    with pytest.raises(training.NotEnoughData, match="al menos 300"):
        training.train(request(samples=real_samples(100)), synthetic)


def test_missing_features_are_filled():
    frame = training.to_frame(request())
    assert not frame.isna().any().any()
    assert frame["signal_strength"].between(-100, 0).all()


def test_samples_are_ordered_by_time():
    samples = real_samples(400)
    shuffled = samples[200:] + samples[:200]
    frame = training.to_frame(TrainingRequest.model_validate({"version": "real-x-1", "samples": shuffled}))
    assert frame["latency"].iloc[0] == pytest.approx(samples[0]["latency"])


def test_decision_rules():
    def m(f1: float, fpr: float) -> TrainingMetrics:
        return TrainingMetrics(precision=0.9, recall=0.9, f1=f1, false_positive_rate=fpr)

    assert training.decide(m(0.90, 0.05), m(0.80, 0.02))[0]           # clearly better at finding faults
    promote, reason = training.decide(m(0.79, 0.02), m(0.80, 0.10))  # about as good, fewer false alarms
    assert promote and "menos falsas alarmas" in reason
    promote, reason = training.decide(m(0.70, 0.01), m(0.80, 0.10))  # finds fewer faults
    assert not promote and "Se sigue usando el actual" in reason
    assert not training.decide(m(0.80, 0.10), m(0.80, 0.10))[0]      # no improvement


@pytest.fixture
def keep_detector(client):
    """The client is shared by every test: put the synthetic model back after a test that replaces it."""
    from app.main import app
    original = app.state.detector
    yield
    app.state.detector = original


def test_train_endpoint_puts_the_new_model_in_use(client, keep_detector):
    response = client.post("/api/v1/model/train", json={"version": "real-20261019-1", "samples": real_samples()})

    body = response.json()
    assert response.status_code == 200
    assert body["decision"] == "PROMOTED" and body["active"] is True
    assert {"precision", "recall", "f1", "falsePositiveRate"} <= body["candidate"].keys()
    info = client.get("/api/v1/model").json()
    assert info["modelVersion"] == "real-20261019-1" and info["realData"] is True and info["trainedSamples"] == 600


def test_train_endpoint_requires_api_key_and_enough_data(client, keep_detector):
    assert client.post("/api/v1/model/train", headers={"X-API-Key": "wrong"},
                       json={"version": "real-1-1", "samples": real_samples(300)}).status_code == 401
    response = client.post("/api/v1/model/train", json={"version": "real-1-1", "samples": real_samples(50)})
    assert response.status_code == 422 and "al menos 300" in response.json()["detail"]
    assert client.post("/api/v1/model/train",
                       json={"version": "Bad Name!", "samples": real_samples(300)}).status_code == 422
