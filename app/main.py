import logging
import os
import secrets
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status

from app.model_service import AnomalyDetectionService
from app.schemas import AnalysisRequest, AnalysisResponse, ModelInfo

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s - %(message)s")

MODEL_PATH = os.getenv("AI_MODEL_PATH", "models/anomaly_model.joblib")
API_KEY = os.getenv("AI_API_KEY")


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.detector = AnomalyDetectionService.load_or_train(MODEL_PATH)
    yield


app = FastAPI(title="WiFiSense AI", version="1.0.0", lifespan=lifespan)


def verify_api_key(x_api_key: str | None = Header(default=None)) -> None:
    """Only the backend calls this service; the shared key is optional for local development."""
    if API_KEY and not secrets.compare_digest(x_api_key or "", API_KEY):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")


def detector(request: Request) -> AnomalyDetectionService:
    return request.app.state.detector


@app.get("/health")
def health() -> dict:
    return {"status": "UP"}


@app.get("/api/v1/model", response_model=ModelInfo, response_model_by_alias=True,
         dependencies=[Depends(verify_api_key)])
def model_info(service: AnomalyDetectionService = Depends(detector)) -> ModelInfo:
    return service.info()


@app.post("/api/v1/anomalies/detect", response_model=AnalysisResponse, response_model_by_alias=True,
          dependencies=[Depends(verify_api_key)])
def detect_anomalies(payload: AnalysisRequest,
                     service: AnomalyDetectionService = Depends(detector)) -> AnalysisResponse:
    return service.detect(payload)
