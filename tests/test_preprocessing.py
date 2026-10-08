from datetime import datetime, timedelta

import numpy as np

from app import preprocessing
from app.schemas import MeasurementInput


def test_frame_is_sorted_chronologically():
    now = datetime(2026, 10, 1, 12, 0)
    later = MeasurementInput(latency=50, jitter=1, packet_loss=0, timestamp=now + timedelta(minutes=5))
    earlier = MeasurementInput(latency=10, jitter=1, packet_loss=0, timestamp=now)

    frame = preprocessing.to_frame([later, earlier])

    assert list(frame["latency"]) == [10, 50]


def test_missing_values_are_imputed_and_reported():
    frame = preprocessing.to_frame([MeasurementInput(latency=10, jitter=1, packet_loss=0)])
    medians = {feature: 1.0 for feature in preprocessing.FEATURES}

    filled, imputed = preprocessing.impute(frame, medians)

    assert not filled.isna().any().any()
    assert "bandwidth" in imputed and "latency" not in imputed


def test_transform_log_scales_heavy_tailed_features():
    frame = preprocessing.to_frame([MeasurementInput(latency=99, jitter=0, packet_loss=5, bandwidth=0)])

    result = preprocessing.transform(frame.fillna(0))

    assert np.isclose(result.loc[0, "latency"], np.log1p(99))
    assert result.loc[0, "packet_loss"] == 5
