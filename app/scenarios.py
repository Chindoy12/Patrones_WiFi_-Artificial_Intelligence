"""Labeled synthetic Wi-Fi fault scenarios used to evaluate the detector and the diagnosis.

There are no labeled anomalies from real networks yet, so each fault is simulated by degrading healthy samples the
way it degrades a real network. The generator uses a different seed than the training baseline so the evaluation
never sees the training samples. Intensity is random: mild faults are deliberately hard to detect.
"""
import numpy as np
import pandas as pd

from app.model_service import generate_baseline
from app.preprocessing import FEATURES

NORMAL = "NORMAL"

# For each fault: feature -> (operation, strongest effect). "mul" multiplies the value (log-scaled by intensity),
# "add" adds up to that amount and "set" moves the value toward a fixed level.
FAULTS: dict[str, dict[str, tuple[str, float]]] = {
    "CONGESTION": {
        "latency": ("mul", 8.0), "jitter": ("mul", 6.0), "connected_devices": ("add", 90.0),
        "traffic_volume": ("mul", 5.0), "bandwidth": ("mul", 0.25), "packet_loss": ("add", 3.0),
    },
    "INTERFERENCE": {
        "packet_loss": ("add", 20.0), "jitter": ("mul", 8.0), "latency": ("mul", 2.5),
    },
    "WEAK_COVERAGE": {
        "signal_strength": ("set", -88.0), "bandwidth": ("mul", 0.12), "packet_loss": ("add", 6.0),
        "latency": ("mul", 2.0),
    },
    "PROVIDER_ISSUE": {
        "latency": ("mul", 15.0), "bandwidth": ("mul", 0.05), "traffic_volume": ("mul", 0.4),
    },
    "SUSPICIOUS_TRAFFIC": {
        "packet_count": ("mul", 20.0), "traffic_volume": ("mul", 8.0), "latency": ("mul", 1.5),
    },
}

FAULT_TYPES = list(FAULTS)


def degrade(sample: pd.Series, fault: str, intensity: float) -> pd.Series:
    """Applies one fault to a healthy sample. intensity in (0, 1]: 1 is the strongest effect."""
    result = sample.copy()
    for feature, (operation, effect) in FAULTS[fault].items():
        if operation == "mul":
            result[feature] *= effect ** intensity
        elif operation == "add":
            result[feature] += effect * intensity
        else:
            result[feature] += (effect - result[feature]) * intensity
    result["packet_loss"] = min(result["packet_loss"], 100.0)
    result["signal_strength"] = min(max(result["signal_strength"], -100.0), 0.0)
    result["connected_devices"] = round(result["connected_devices"])
    return result


def generate(normal: int = 2000, per_fault: int = 100, seed: int = 7,
             min_intensity: float = 0.25) -> pd.DataFrame:
    """Healthy samples plus `per_fault` degraded samples of each fault, with a `scenario` label column."""
    healthy = generate_baseline(normal + per_fault * len(FAULTS), seed=seed)
    rng = np.random.default_rng(seed + 1)  # separate stream for intensities
    rows = [{**healthy.iloc[i].to_dict(), "scenario": NORMAL} for i in range(normal)]
    position = normal
    for fault in FAULTS:
        for _ in range(per_fault):
            intensity = rng.uniform(min_intensity, 1.0)
            rows.append({**degrade(healthy.iloc[position], fault, intensity).to_dict(), "scenario": fault})
            position += 1
    frame = pd.DataFrame(rows).reset_index(drop=True)
    frame[FEATURES] = frame[FEATURES].astype(float)
    return frame
