import pytest

from app import scenarios
from app.model_service import generate_baseline
from app.preprocessing import FEATURES


@pytest.fixture(scope="module")
def frame():
    return scenarios.generate(normal=200, per_fault=20)


def test_scenarios_are_labeled_and_balanced(frame):
    counts = frame["scenario"].value_counts()

    assert counts[scenarios.NORMAL] == 200
    assert all(counts[fault] == 20 for fault in scenarios.FAULT_TYPES)
    assert list(frame.columns) == FEATURES + ["scenario"]


def test_values_stay_physically_valid(frame):
    assert frame["packet_loss"].between(0, 100).all()
    assert frame["signal_strength"].between(-100, 0).all()
    assert (frame[FEATURES] >= -100).all().all()


def test_each_fault_degrades_its_own_metric(frame):
    medians = frame.groupby("scenario").median()
    normal = medians.loc[scenarios.NORMAL]

    assert medians.loc["CONGESTION", "connected_devices"] > normal["connected_devices"] * 2
    assert medians.loc["INTERFERENCE", "packet_loss"] > normal["packet_loss"] + 5
    assert medians.loc["WEAK_COVERAGE", "signal_strength"] < normal["signal_strength"] - 10
    assert medians.loc["PROVIDER_ISSUE", "bandwidth"] < normal["bandwidth"] / 3
    assert medians.loc["SUSPICIOUS_TRAFFIC", "packet_count"] > normal["packet_count"] * 3


def test_evaluation_data_never_repeats_training_samples(frame):
    training = generate_baseline()

    assert frame[FEATURES].merge(training[FEATURES], how="inner").empty
