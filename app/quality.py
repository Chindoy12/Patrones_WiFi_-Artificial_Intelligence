"""Connection quality from 0 to 100, explained metric by metric.

Each metric is scored with a curve built from usual service requirements (for example, video calls need latency under
150 ms and jitter under 30 ms). The overall score is the weighted mean of the available metrics, but one very bad
metric caps it: a connection with perfect speed and 20 % packet loss is not a good connection. The result also says
which everyday activities the connection can handle and what to try first to improve it.
"""
from bisect import bisect_left
from enum import Enum

from app.schemas_quality import (ActivityResult, MetricResult, MetricStatus, QualityGrade, QualityRequest,
                                 QualityResponse)

MODEL_VERSION = "quality-1.0"

# (value, score) breakpoints, sorted by value. Scores between breakpoints are interpolated linearly.
CURVES: dict[str, list[tuple[float, float]]] = {
    "latency": [(20, 100), (50, 85), (100, 60), (200, 30), (400, 0)],
    "jitter": [(5, 100), (15, 80), (30, 55), (60, 25), (100, 0)],
    "packet_loss": [(0, 100), (0.5, 90), (1, 75), (3, 45), (5, 25), (10, 0)],
    "download": [(1, 5), (5, 30), (10, 50), (25, 75), (50, 90), (100, 100)],
    "download_ratio": [(0.1, 10), (0.3, 40), (0.5, 65), (0.7, 85), (0.9, 100)],
    "upload": [(0.5, 5), (2, 30), (5, 50), (10, 70), (20, 85), (50, 100)],
    "signal": [(-90, 0), (-85, 15), (-75, 45), (-67, 75), (-60, 90), (-50, 100)],
}

WEIGHTS = {"latency": .25, "jitter": .15, "packet_loss": .20, "download": .25, "upload": .10, "signal": .05}

# A single metric below this score keeps the overall score at most this much above it.
BOTTLENECK_MARGIN = 30

LABELS = {
    "latency": ("Latencia", "ms"), "jitter": ("Jitter", "ms"), "packet_loss": ("Pérdida de paquetes", "%"),
    "download": ("Velocidad de bajada", "Mbps"), "upload": ("Velocidad de subida", "Mbps"),
    "signal": ("Intensidad de señal", "dBm"),
}

TIPS = {
    "latency": "La respuesta es lenta: acércate al router o conéctate a la red de 5 GHz, y evita descargas grandes "
               "mientras juegas o haces videollamadas.",
    "jitter": "La conexión es inestable: otro equipo puede estar usando mucho la red; prueba de nuevo cuando esté "
              "más libre o usa cable para lo importante.",
    "packet_loss": "Se pierden datos: suele ser interferencia o mala señal. Cambia el router de lugar, lejos de "
                   "paredes gruesas y del microondas.",
    "download": "La bajada es baja: compárala con lo contratado. Si conectado por cable también es baja, el problema "
                "es del proveedor y puedes reclamar.",
    "upload": "La subida es baja: afecta videollamadas y envío de archivos. Revisa si algún equipo está subiendo "
              "copias de seguridad a la nube.",
    "signal": "La señal llega débil: acércate al router o agrega un repetidor o un sistema de malla.",
}


class Activity(str, Enum):
    BROWSING = "BROWSING"
    VIDEO_CALLS = "VIDEO_CALLS"
    STREAMING_HD = "STREAMING_HD"
    STREAMING_4K = "STREAMING_4K"
    GAMING = "GAMING"


# What each activity needs: minimum download/upload (Mbps), maximum latency/jitter (ms) and loss (%). Core metrics
# must be measured to decide; packet loss is only checked when it was measured, because the browser test of Mi Wi-Fi
# cannot see it (the agent can).
REQUIREMENTS: dict[Activity, dict[str, tuple[str, float, bool]]] = {
    Activity.BROWSING: {"download": (">=", 1, True), "latency": ("<=", 300, True), "packet_loss": ("<=", 5, False)},
    Activity.VIDEO_CALLS: {"download": (">=", 3, True), "upload": (">=", 3, True), "latency": ("<=", 150, True),
                           "jitter": ("<=", 30, True), "packet_loss": ("<=", 2, False)},
    Activity.STREAMING_HD: {"download": (">=", 5, True), "packet_loss": ("<=", 3, False)},
    Activity.STREAMING_4K: {"download": (">=", 25, True), "packet_loss": ("<=", 2, False)},
    Activity.GAMING: {"latency": ("<=", 60, True), "jitter": ("<=", 20, True), "packet_loss": ("<=", 1, False)},
}

ACTIVITY_LABELS = {
    Activity.BROWSING: "Navegar y correo", Activity.VIDEO_CALLS: "Videollamadas y clases",
    Activity.STREAMING_HD: "Video en HD", Activity.STREAMING_4K: "Video en 4K", Activity.GAMING: "Juegos en línea",
}

GRADE_LABELS = {QualityGrade.EXCELLENT: "Excelente", QualityGrade.GOOD: "Buena", QualityGrade.FAIR: "Regular",
                QualityGrade.POOR: "Mala"}


def curve_score(curve: list[tuple[float, float]], value: float) -> float:
    """Linear interpolation on the breakpoints; values outside them take the score of the nearest end."""
    values = [v for v, _ in curve]
    if value <= values[0]:
        return curve[0][1]
    if value >= values[-1]:
        return curve[-1][1]
    i = bisect_left(values, value)
    (x0, y0), (x1, y1) = curve[i - 1], curve[i]
    return y0 + (y1 - y0) * (value - x0) / (x1 - x0)


def metric_values(request: QualityRequest) -> dict[str, float]:
    values = {"latency": request.latency_ms, "jitter": request.jitter_ms, "packet_loss": request.packet_loss_pct,
              "download": request.download_mbps, "upload": request.upload_mbps, "signal": request.signal_dbm}
    return {metric: value for metric, value in values.items() if value is not None}


def metric_score(metric: str, value: float, contracted_mbps: float | None) -> float:
    if metric == "download" and contracted_mbps:
        return curve_score(CURVES["download_ratio"], value / contracted_mbps)
    return curve_score(CURVES[metric], value)


def status_of(score: float) -> MetricStatus:
    if score >= 75:
        return MetricStatus.GOOD
    if score >= 45:
        return MetricStatus.FAIR
    return MetricStatus.POOR


def grade_of(score: float) -> QualityGrade:
    if score >= 85:
        return QualityGrade.EXCELLENT
    if score >= 70:
        return QualityGrade.GOOD
    if score >= 50:
        return QualityGrade.FAIR
    return QualityGrade.POOR


def suitable(activity: Activity, values: dict[str, float]) -> bool | None:
    """True or False when the core metrics were measured; None when one of them is missing."""
    checks = []
    for metric, (operator, limit, core) in REQUIREMENTS[activity].items():
        if metric not in values:
            if core:
                return None
            continue
        checks.append(values[metric] >= limit if operator == ">=" else values[metric] <= limit)
    return all(checks)


def score(request: QualityRequest) -> QualityResponse:
    values = metric_values(request)
    scores = {metric: metric_score(metric, value, request.contracted_mbps) for metric, value in values.items()}
    total_weight = sum(WEIGHTS[m] for m in scores)
    weighted = sum(WEIGHTS[m] * s for m, s in scores.items()) / total_weight
    overall = round(min(weighted, min(scores.values()) + BOTTLENECK_MARGIN))
    grade = grade_of(overall)

    metrics = [MetricResult(metric=m, label=LABELS[m][0], value=round(values[m], 2), unit=LABELS[m][1],
                            score=round(s), status=status_of(s)) for m, s in scores.items()]
    activities = [ActivityResult(activity=a.value, label=ACTIVITY_LABELS[a], suitable=suitable(a, values))
                  for a in Activity]
    weakest = sorted((m for m in scores if scores[m] < 75), key=scores.get)
    return QualityResponse(
        score=overall, grade=grade, grade_label=GRADE_LABELS[grade], metrics=metrics, activities=activities,
        tips=[TIPS[m] for m in weakest[:2]],
        contracted_ratio=(round(request.download_mbps / request.contracted_mbps, 2)
                          if request.download_mbps is not None and request.contracted_mbps else None),
        model_version=MODEL_VERSION,
    )
