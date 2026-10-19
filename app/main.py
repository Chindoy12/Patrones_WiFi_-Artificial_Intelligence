import logging
import os
import secrets
import threading
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status

from app import channel, evaluation, quality, security, training
from app.llm_advisor import ClaudeAdvisor
from app.model_service import AnomalyDetectionService
from app.schemas import (AnalysisRequest, AnalysisResponse, EvaluationReport, ModelInfo, TrainingRequest,
                         TrainingResult)
from app.schemas_channel import ChannelRequest, ChannelResponse
from app.schemas_quality import QualityRequest, QualityResponse
from app.schemas_security import SecurityRequest, SecurityResponse

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s - %(message)s")

MODEL_PATH = os.getenv("AI_MODEL_PATH", "models/anomaly_model.joblib")
API_KEY = os.getenv("AI_API_KEY")
logger = logging.getLogger(__name__)


class EvaluationRun:
    """Runs the model comparison once in the background so startup and detection are never delayed."""

    def __init__(self):
        self.report: EvaluationReport | None = None
        self.failed = False
        self._done = threading.Event()

    def start(self) -> "EvaluationRun":
        threading.Thread(target=self._run, name="model-evaluation", daemon=True).start()
        return self

    def wait(self, timeout: float) -> bool:
        return self._done.wait(timeout)

    def _run(self) -> None:
        try:
            self.report = evaluation.evaluate()
            logger.info("Model evaluation ready")
        except Exception:  # the comparison is informative; detection keeps working without it
            logger.exception("Model evaluation failed")
            self.failed = True
        finally:
            self._done.set()


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.detector = AnomalyDetectionService.load_or_train(MODEL_PATH)
    app.state.advisor = ClaudeAdvisor.from_env()
    app.state.evaluation = EvaluationRun().start()
    yield


app = FastAPI(title="WiFiSense AI", version="1.3.0", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)


def verify_api_key(x_api_key: str | None = Header(default=None)) -> None:
    """Only the backend calls this service; the shared key is optional for local development."""
    if API_KEY and not secrets.compare_digest(x_api_key or "", API_KEY):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")


def detector(request: Request) -> AnomalyDetectionService:
    return request.app.state.detector


def advisor(request: Request) -> ClaudeAdvisor | None:
    return request.app.state.advisor


@app.get("/health")
def health() -> dict:
    return {"status": "UP"}


@app.get("/api/v1/model", response_model=ModelInfo, response_model_by_alias=True,
         dependencies=[Depends(verify_api_key)])
def model_info(service: AnomalyDetectionService = Depends(detector),
               claude: ClaudeAdvisor | None = Depends(advisor)) -> ModelInfo:
    return service.info(claude.model if claude else "reglas")


_training_lock = threading.Lock()


@app.post("/api/v1/model/train", response_model=TrainingResult, response_model_by_alias=True,
          dependencies=[Depends(verify_api_key)])
def train_model(payload: TrainingRequest, request: Request) -> TrainingResult:
    """Trains a model with real measurements sent by the backend and puts it in use only if it is better (or rebuilds
    the one already promoted, after a restart). Detection keeps using the current model meanwhile."""
    with _training_lock:
        try:
            result, model = training.train(payload, request.app.state.detector)
        except training.NotEnoughData as error:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(error))
        if model is not None:
            request.app.state.detector = model
            try:
                model.save(MODEL_PATH)
            except OSError:
                logger.warning("The new model is in use but could not be saved to %s", MODEL_PATH)
            logger.info("Model %s in use (%s)", model.version, result.decision)
        return result


@app.get("/api/v1/model/evaluation", response_model=EvaluationReport, response_model_by_alias=True,
         dependencies=[Depends(verify_api_key)])
def model_evaluation(request: Request) -> EvaluationReport:
    run: EvaluationRun = request.app.state.evaluation
    if run.report is None:
        detail = ("La evaluación del modelo no está disponible." if run.failed
                  else "La evaluación del modelo está en curso. Intenta de nuevo en unos segundos.")
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=detail)
    return run.report


@app.post("/api/v1/anomalies/detect", response_model=AnalysisResponse, response_model_by_alias=True,
          dependencies=[Depends(verify_api_key)])
def detect_anomalies(payload: AnalysisRequest,
                     service: AnomalyDetectionService = Depends(detector),
                     claude: ClaudeAdvisor | None = Depends(advisor)) -> AnalysisResponse:
    result = service.detect(payload)
    # Claude is only asked when there is something to explain: the agent reports every few minutes and a normal
    # result already has nothing to recommend, so this keeps the API cost (and latency) proportional to problems.
    return claude.enrich(result, payload) if claude and result.anomaly_detected else result


@app.post("/api/v1/quality/score", response_model=QualityResponse, response_model_by_alias=True,
          dependencies=[Depends(verify_api_key)])
def quality_score(payload: QualityRequest) -> QualityResponse:
    """0-100 quality of one connection test or measurement, with what it is good for and what to improve."""
    return quality.score(payload)


@app.post("/api/v1/security/assess", response_model=SecurityResponse, response_model_by_alias=True,
          dependencies=[Depends(verify_api_key)])
def security_assess(payload: SecurityRequest) -> SecurityResponse:
    """0-100 security audit of a home network from what the agent saw: encryption, router ports, new devices."""
    return security.assess(payload)


@app.post("/api/v1/channel/recommend", response_model=ChannelResponse, response_model_by_alias=True,
          dependencies=[Depends(verify_api_key)])
def channel_recommend(payload: ChannelRequest) -> ChannelResponse:
    """Channel with the least interference from the neighbouring networks the agent saw, and whether to move to it."""
    return channel.recommend(payload)
