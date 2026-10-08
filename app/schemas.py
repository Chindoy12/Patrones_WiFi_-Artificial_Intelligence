from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel


class CamelModel(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)


class Severity(str, Enum):
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class MeasurementInput(CamelModel):
    latency: float = Field(ge=0, description="Latency in ms")
    jitter: float = Field(ge=0, description="Jitter in ms")
    packet_loss: float = Field(ge=0, le=100, description="Packet loss in %")
    bandwidth: float | None = Field(default=None, ge=0, description="Mbps")
    signal_strength: float | None = Field(default=None, ge=-100, le=0, description="RSSI in dBm")
    traffic_volume: float | None = Field(default=None, ge=0, description="MB per interval")
    connected_devices: int | None = Field(default=None, ge=0)
    packet_count: int | None = Field(default=None, ge=0)
    timestamp: datetime | None = None


class AnalysisRequest(CamelModel):
    network_id: int
    simulated_data: bool = Field(description="True when measurements come from the simulation data source")
    measurements: list[MeasurementInput] = Field(min_length=1, max_length=1000)


class AnalysisResponse(CamelModel):
    anomaly_detected: bool
    anomaly_score: float = Field(ge=0, le=1)
    severity: Severity
    message: str
    recommendation: str | None
    contributing_features: list[str]
    anomalous_samples: int
    sample_size: int
    imputed_features: list[str]
    model_version: str
    simulated_data: bool


class ModelInfo(CamelModel):
    algorithm: str
    model_version: str
    features: list[str]
    threshold: float
    trained_on: str
