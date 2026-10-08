import numpy as np
import pandas as pd

from app.schemas import MeasurementInput

FEATURES = [
    "latency",
    "jitter",
    "packet_loss",
    "bandwidth",
    "signal_strength",
    "traffic_volume",
    "connected_devices",
    "packet_count",
]

# Heavy-tailed metrics are log-scaled so a few large values do not dominate the splits.
LOG_FEATURES = ["latency", "jitter", "bandwidth", "traffic_volume", "packet_count"]


def to_frame(measurements: list[MeasurementInput]) -> pd.DataFrame:
    rows = [m.model_dump(include=set(FEATURES)) for m in measurements]
    frame = pd.DataFrame(rows, columns=FEATURES).astype(float)
    timestamps = [m.timestamp for m in measurements]
    if all(timestamps):
        frame = frame.iloc[np.argsort(timestamps, kind="stable")].reset_index(drop=True)
    return frame


def impute(frame: pd.DataFrame, medians: dict[str, float]) -> tuple[pd.DataFrame, list[str]]:
    """Fills missing values with baseline medians and reports which features were imputed."""
    imputed = [f for f in FEATURES if frame[f].isna().any()]
    return frame.fillna(value=medians), imputed


def transform(frame: pd.DataFrame) -> pd.DataFrame:
    result = frame[FEATURES].copy()
    result[LOG_FEATURES] = np.log1p(result[LOG_FEATURES].clip(lower=0))
    return result


def robust_deviation(row: pd.Series, medians: pd.Series, spreads: pd.Series) -> pd.Series:
    """Robust z-score of a transformed sample against the baseline (median / IQR)."""
    return (row - medians) / spreads.replace(0, 1)
