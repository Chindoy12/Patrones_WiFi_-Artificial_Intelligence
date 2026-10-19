"""Training the anomaly model with the real measurements of the networks, and deciding whether it replaces the model in
use.

There are still no real faults labeled by hand, so the test is built from the real data itself:

* the most recent 20 % of the measurements (by time) is kept apart as **normal** test data: a good model raises few
  false alarms on the real behaviour of these networks;
* a copy of those same measurements is degraded with the five simulated faults (congestion, interference, weak
  coverage, provider failure, suspicious traffic; random intensity) as **faults**: a good model still finds them.

The new model (trained with the older 80 %) and the model in use are measured on exactly the same test. The new one
replaces it only if it finds the faults at least as well (F1 at most 0.02 lower) with fewer false alarms, or clearly
better (F1 0.02 higher). When it is promoted, the model put in use is trained with all the measurements.
"""
from __future__ import annotations

from datetime import datetime, timezone

import numpy as np
import pandas as pd

from app import evaluation, model_service, scenarios
from app.preprocessing import FEATURES
from app.schemas import TrainingMetrics, TrainingRequest, TrainingResult

MIN_SAMPLES = 300
TEST_SHARE = 0.2
F1_MARGIN = 0.02


class NotEnoughData(ValueError):
    pass


def to_frame(request: TrainingRequest) -> pd.DataFrame:
    """The samples ordered by time, with every feature filled: a missing value takes the median of the real data and
    a feature no network measured (for example the signal of a computer on cable) the synthetic baseline median."""
    rows = [s.model_dump(include=set(FEATURES) | {"timestamp"}) for s in request.samples]
    frame = pd.DataFrame(rows)
    for feature in FEATURES:
        if feature not in frame:
            frame[feature] = np.nan
    if frame["timestamp"].notna().all():
        frame = frame.sort_values("timestamp", kind="stable")
    frame = frame[FEATURES].astype(float).reset_index(drop=True)
    baseline = model_service.generate_baseline(500).median()
    medians = frame.median().fillna(baseline)
    return frame.fillna(medians)


def faults_from(normal: pd.DataFrame, seed: int) -> pd.DataFrame:
    """The real test measurements degraded with each simulated fault (the same number of each)."""
    rng = np.random.default_rng(seed + 1)
    rows = []
    for i, (_, sample) in enumerate(normal.iterrows()):
        fault = scenarios.FAULT_TYPES[i % len(scenarios.FAULT_TYPES)]
        rows.append(scenarios.degrade(sample.copy(), fault, rng.uniform(0.25, 1.0)))
    return pd.DataFrame(rows, columns=FEATURES).astype(float)


def metrics(service: model_service.AnomalyDetectionService, normal: pd.DataFrame,
            faults: pd.DataFrame) -> TrainingMetrics:
    test = pd.concat([normal, faults], ignore_index=True)
    truth = np.array([False] * len(normal) + [True] * len(faults))
    precision, recall, f1, fpr = evaluation._binary_metrics(truth, service.flag_raw(test))
    return TrainingMetrics(precision=round(float(precision), 4), recall=round(float(recall), 4), f1=round(float(f1), 4),
                           false_positive_rate=round(float(fpr), 4))


def decide(candidate: TrainingMetrics, current: TrainingMetrics) -> tuple[bool, str]:
    """Whether the new model replaces the one in use, and why (in Spanish, with decimal commas)."""
    def pct(value: float) -> str:
        return f"{value * 100:.1f} %".replace(".", ",")

    def f1(value: float) -> str:
        return f"{value:.2f}".replace(".", ",")
    if candidate.f1 >= current.f1 + F1_MARGIN:
        return True, (f"Encuentra mejor las fallas: F1 {f1(candidate.f1)} frente a {f1(current.f1)} del modelo en uso, "
                      f"con {pct(candidate.false_positive_rate)} de falsas alarmas.")
    if candidate.f1 >= current.f1 - F1_MARGIN and candidate.false_positive_rate < current.false_positive_rate:
        return True, (f"Da menos falsas alarmas con estas redes ({pct(candidate.false_positive_rate)} frente a "
                      f"{pct(current.false_positive_rate)}) y encuentra las fallas igual de bien (F1 "
                      f"{f1(candidate.f1)} frente a {f1(current.f1)}).")
    return False, (f"No es mejor que el modelo en uso: F1 {f1(candidate.f1)} frente a {f1(current.f1)} y "
                   f"{pct(candidate.false_positive_rate)} frente a {pct(current.false_positive_rate)} de falsas "
                   "alarmas. Se sigue usando el actual.")


def describe(samples: int) -> str:
    return f"{samples} mediciones reales de las redes de WiFiSense (sensores y agentes)"


def train(request: TrainingRequest,
          current: model_service.AnomalyDetectionService) -> tuple[TrainingResult, model_service.AnomalyDetectionService | None]:
    """Returns the result and, when the new model must be put in use, that model (trained with all the samples)."""
    if len(request.samples) < MIN_SAMPLES:
        raise NotEnoughData(f"Se necesitan al menos {MIN_SAMPLES} mediciones reales para entrenar; hay "
                            f"{len(request.samples)}. Deja los sensores encendidos unos días más.")
    data = to_frame(request)
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")

    def production() -> model_service.AnomalyDetectionService:
        return model_service.AnomalyDetectionService.train(
            data, seed=request.seed, version=request.version, trained_on=describe(len(data)), samples=len(data),
            trained_at=now)

    if request.restore:
        return TrainingResult(version=request.version, samples=len(data), train_samples=len(data), test_normal=0,
                              test_faults=0, decision="RESTORED", reason="Se reconstruyó el modelo en uso.",
                              current_version=current.version, active=True), production()

    split = int(len(data) * (1 - TEST_SHARE))
    train_part, normal = data.iloc[:split], data.iloc[split:].reset_index(drop=True)
    faults = faults_from(normal, request.seed)
    candidate_service = model_service.AnomalyDetectionService.train(train_part, seed=request.seed)
    candidate, in_use = metrics(candidate_service, normal, faults), metrics(current, normal, faults)
    promote, reason = decide(candidate, in_use)
    result = TrainingResult(version=request.version, samples=len(data), train_samples=len(train_part),
                            test_normal=len(normal), test_faults=len(faults),
                            decision="PROMOTED" if promote else "REJECTED", reason=reason, candidate=candidate,
                            current=in_use, current_version=current.version, active=promote and request.activate)
    return result, production() if result.active else None
