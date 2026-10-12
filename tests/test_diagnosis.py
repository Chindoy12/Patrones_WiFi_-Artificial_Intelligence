import pytest

from app import diagnosis
from app.diagnosis import AnomalyType
from app.preprocessing import FEATURES


def deviations(**values):
    return {feature: values.get(feature, 0.0) for feature in FEATURES}


@pytest.mark.parametrize("values, expected", [
    ({"connected_devices": 5, "traffic_volume": 2, "latency": 2}, AnomalyType.CONGESTION),
    ({"packet_loss": 20, "jitter": 3}, AnomalyType.INTERFERENCE),
    ({"signal_strength": 3, "bandwidth": 2, "packet_loss": 4}, AnomalyType.WEAK_COVERAGE),
    ({"latency": 4, "bandwidth": 3}, AnomalyType.PROVIDER_ISSUE),
    ({"packet_count": 4, "traffic_volume": 2}, AnomalyType.SUSPICIOUS_TRAFFIC),
])
def test_each_fault_signature_is_recognized(values, expected):
    assert diagnosis.diagnose(deviations(**values)) == expected


def test_weak_pattern_is_not_forced_into_a_fault():
    assert diagnosis.diagnose(deviations(jitter=1.0)) == AnomalyType.UNKNOWN


def test_extreme_metric_is_capped_so_it_does_not_hide_the_signal():
    # Packet loss is extreme, but the weak signal explains it: coverage, not interference.
    weak_signal = deviations(packet_loss=60, signal_strength=4, bandwidth=3)

    assert diagnosis.diagnose(weak_signal) == AnomalyType.WEAK_COVERAGE


def test_every_fault_has_spanish_label_explanation_and_action():
    for fault in diagnosis.SIGNATURES:
        assert diagnosis.describe(fault).startswith(f"Causa probable: {diagnosis.LABELS[fault]}")
        assert diagnosis.ACTIONS[fault]
    assert diagnosis.describe(AnomalyType.NONE) is None
