"""Explains an anomaly by naming its most likely cause.

Isolation Forest says *that* a measurement is unusual, not *why*. Each fault leaves a recognizable signature in the
harmful deviations (robust z-scores where a positive value always means "worse"): congestion raises connected
devices and traffic, interference raises packet loss and jitter while the signal stays good, and so on. The
signatures are written from network domain knowledge, so the diagnosis stays explainable and auditable.
"""
from enum import Enum

# Large deviations are capped so one extreme metric (packet loss reaches z > 20) cannot hide the others.
DEVIATION_CAP = 6.0
# Below this signature score the pattern does not match any known fault.
MIN_SCORE = 1.5


class AnomalyType(str, Enum):
    NONE = "NONE"
    CONGESTION = "CONGESTION"
    INTERFERENCE = "INTERFERENCE"
    WEAK_COVERAGE = "WEAK_COVERAGE"
    PROVIDER_ISSUE = "PROVIDER_ISSUE"
    SUSPICIOUS_TRAFFIC = "SUSPICIOUS_TRAFFIC"
    UNKNOWN = "UNKNOWN"


# Positive weight: the fault raises that harmful deviation. Negative weight: the fault leaves it normal, so a high
# value there points to a different cause.
SIGNATURES: dict[AnomalyType, dict[str, float]] = {
    AnomalyType.CONGESTION: {
        "connected_devices": 1.0, "traffic_volume": 0.5, "latency": 0.3, "jitter": 0.3, "packet_count": -0.4,
    },
    AnomalyType.INTERFERENCE: {
        "packet_loss": 0.6, "jitter": 0.6, "signal_strength": -0.8, "connected_devices": -0.6, "bandwidth": -0.3,
    },
    AnomalyType.WEAK_COVERAGE: {
        "signal_strength": 1.2, "bandwidth": 0.4, "packet_loss": 0.2,
    },
    AnomalyType.PROVIDER_ISSUE: {
        "latency": 0.6, "bandwidth": 0.6, "packet_loss": -0.3, "jitter": -0.3, "connected_devices": -0.5,
        "signal_strength": -0.6,
    },
    AnomalyType.SUSPICIOUS_TRAFFIC: {
        "packet_count": 1.0, "traffic_volume": 0.4, "connected_devices": -0.5,
    },
}

LABELS = {
    AnomalyType.NONE: "sin anomalía",
    AnomalyType.CONGESTION: "congestión de la red",
    AnomalyType.INTERFERENCE: "interferencia de radio",
    AnomalyType.WEAK_COVERAGE: "cobertura débil",
    AnomalyType.PROVIDER_ISSUE: "falla del proveedor de internet",
    AnomalyType.SUSPICIOUS_TRAFFIC: "tráfico sospechoso",
    AnomalyType.UNKNOWN: "causa no identificada",
}

EXPLANATIONS = {
    AnomalyType.CONGESTION: "Hay más dispositivos y tráfico de lo habitual, y la latencia sube con ellos.",
    AnomalyType.INTERFERENCE: "Se pierden paquetes y el jitter sube aunque la señal es buena: el canal tiene ruido.",
    AnomalyType.WEAK_COVERAGE: "La señal llega débil y con ella caen la velocidad y la estabilidad.",
    AnomalyType.PROVIDER_ISSUE: "La red local está bien, pero la salida a internet es lenta: el problema parece "
                                "estar en el proveedor.",
    AnomalyType.SUSPICIOUS_TRAFFIC: "El número de paquetes es muy superior al normal sin más dispositivos "
                                    "conectados: puede ser un escaneo, una inundación o una descarga masiva.",
    AnomalyType.UNKNOWN: "Las métricas no coinciden con ninguna falla conocida; conviene revisarlas una a una.",
}

ACTIONS = {
    AnomalyType.CONGESTION: "Distribuye los clientes entre puntos de acceso, limita el ancho de banda por cliente "
                            "o agrega capacidad en la zona.",
    AnomalyType.INTERFERENCE: "Cambia a un canal menos ocupado (preferiblemente en 5 GHz) y aleja el punto de acceso "
                              "de microondas, cámaras inalámbricas y otras fuentes de ruido.",
    AnomalyType.WEAK_COVERAGE: "Reubica el punto de acceso o agrega un repetidor o un nodo de malla cerca de esta zona.",
    AnomalyType.PROVIDER_ISSUE: "Reinicia el módem y verifica el estado del servicio con el proveedor; si persiste, "
                                "reporta la falla con estas mediciones.",
    AnomalyType.SUSPICIOUS_TRAFFIC: "Identifica en la captura de tráfico qué equipo genera los paquetes y aíslalo "
                                    "si no reconoces la actividad.",
    AnomalyType.UNKNOWN: "Revisa los cambios recientes de configuración y compara con mediciones anteriores.",
}


def signature_scores(harmful: dict[str, float]) -> dict[AnomalyType, float]:
    capped = {feature: min(max(value, 0.0), DEVIATION_CAP) for feature, value in harmful.items()}
    return {fault: sum(weight * capped.get(feature, 0.0) for feature, weight in weights.items())
            for fault, weights in SIGNATURES.items()}


def diagnose(harmful: dict[str, float]) -> AnomalyType:
    """Most likely fault for an anomalous sample, or UNKNOWN when no signature matches well enough."""
    scores = signature_scores(harmful)
    best = max(scores, key=scores.get)
    return best if scores[best] >= MIN_SCORE else AnomalyType.UNKNOWN


def describe(anomaly_type: AnomalyType) -> str | None:
    if anomaly_type == AnomalyType.NONE:
        return None
    return f"Causa probable: {LABELS[anomaly_type]}. {EXPLANATIONS[anomaly_type]}"
