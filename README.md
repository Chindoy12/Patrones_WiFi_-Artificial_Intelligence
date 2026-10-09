# WiFiSense-ai

Servicio independiente de detección de anomalías en redes Wi-Fi. Lo llama **solo el backend**: no recibe
peticiones del navegador y no accede a la base de datos; analiza exactamente los datos que el backend le envía.

## Tecnologías

Python 3.13 · FastAPI · Pydantic v2 · NumPy · Pandas · scikit-learn (Isolation Forest) · joblib · Uvicorn · pytest

## Estructura

```text
app/main.py           endpoints, carga del modelo al arrancar, API key
app/schemas.py        contrato de entrada/salida (JSON en camelCase)
app/preprocessing.py  orden cronológico, imputación, transformación logarítmica, desviación robusta
app/model_service.py  entrenamiento, persistencia, detección, severidad y explicación
tests/                preprocesamiento, modelo y API
```

## Modelo

**Isolation Forest** aísla puntos con cortes aleatorios; los puntos anómalos se aíslan con menos cortes. Se eligió
porque:

- es **no supervisado**: no existen anomalías etiquetadas de redes reales para entrenar un clasificador;
- funciona bien con pocas variables numéricas y es rápido de entrenar y de consultar;
- su puntaje normalizado `s(x) ∈ (0, 1)` es interpretable: cerca de 1 = anómalo.

**Entrenamiento.** Al arrancar, si no existe el archivo de `AI_MODEL_PATH`, se entrena con una línea base
**sintética** de redes sanas (5 000 muestras generadas en `generate_baseline`) y se guarda con joblib. Es una
decisión honesta y explícita: no hay datos reales etiquetados. `GET /api/v1/model` lo declara en `trainedOn`.

**Variables:** `latency`, `jitter`, `packet_loss`, `bandwidth`, `signal_strength`, `traffic_volume`,
`connected_devices`, `packet_count`.

**Preprocesamiento.** Orden por timestamp, imputación con la mediana de la línea base (las variables imputadas se
devuelven en `imputedFeatures`), `log1p` sobre variables de cola larga.

**Decisión.** Se evalúa la **última** medición de la ventana. Es anómala si el bosque la marca como outlier
(contaminación 2 %). Severidad según la distancia al umbral: `LOW` < 0.04 ≤ `MEDIUM` < 0.10 ≤ `HIGH`.
`contributingFeatures` lista las variables con desviación robusta > 2 en la dirección dañina (más latencia, menos
señal…), y de ahí sale la recomendación.

## Recomendaciones con Claude (opcional)

Si se define `ANTHROPIC_API_KEY`, después de la detección `ClaudeAdvisor` (`app/llm_advisor.py`) pide a Claude
hasta 3 recomendaciones en español y reemplaza la recomendación por reglas. La respuesta indica el origen en
`recommendationSource` (`CLAUDE` o `RULES`).

- Modelo por defecto: `claude-haiku-4-5-20251001` (cambiable con `CLAUDE_MODEL`).
- Solo se envían métricas agregadas y el veredicto del modelo; nunca IP, MAC, nombres de usuario ni identificadores.
- Si la API falla, se agota la cuota o no hay clave, se usa la recomendación por reglas y el análisis no se interrumpe.
- La API de Claude se paga aparte en la Consola de Claude; una suscripción Claude Pro no la incluye.

## Endpoints

| Método | Ruta | Descripción |
|---|---|---|
| GET | `/health` | Estado del servicio (público) |
| GET | `/api/v1/model` | Algoritmo, versión, variables, umbral y origen del entrenamiento |
| POST | `/api/v1/anomalies/detect` | Detecta anomalías en una ventana de mediciones |

Si `AI_API_KEY` está definida, los endpoints `/api/v1/**` exigen la cabecera `X-API-Key`.

### Entrada

```json
{
  "networkId": 3,
  "simulatedData": true,
  "measurements": [
    { "latency": 74.1, "jitter": 21.3, "packetLoss": 4.2, "bandwidth": 41.0, "signalStrength": -74,
      "trafficVolume": 220.5, "connectedDevices": 66, "packetCount": 180000, "timestamp": "2026-10-05T22:00:00Z" }
  ]
}
```

Entre 1 y 1 000 mediciones. `latency`, `jitter` y `packetLoss` son obligatorios; el resto es opcional.

### Salida

```json
{
  "anomalyDetected": true,
  "anomalyScore": 0.7103,
  "severity": "HIGH",
  "message": "Comportamiento inusual detectado en: pérdida de paquetes, dispositivos conectados, jitter",
  "recommendation": "Revisa interferencias de radio y retransmisiones; considera cambiar de canal. ...",
  "recommendationSource": "RULES",
  "contributingFeatures": ["packet_loss", "connected_devices", "jitter"],
  "anomalousSamples": 50,
  "sampleSize": 50,
  "imputedFeatures": [],
  "modelVersion": "isolation-forest-1.0",
  "simulatedData": true
}
```

`simulatedData` se devuelve tal como llegó: el resultado nunca oculta que los datos eran simulados.

## Ejecución

```bash
pip install -r requirements.txt
cp .env.example .env                       # AI_API_KEY igual a la del backend
export $(grep -v '^#' .env | xargs)
uvicorn app.main:app --port 8000
pytest                                     # 19 pruebas
docker build -t wifisense-ai . && docker run -p 8000:8000 -e AI_API_KEY=... wifisense-ai
```

## Integración con el backend

`AnomalyDetectionStrategy` (WiFiSense-backend) arma la ventana con las últimas 50 mediciones de la red, cruza el
tráfico por timestamp y llama a `POST /api/v1/anomalies/detect` mediante `AiAnalysisClient`. El backend guarda la
respuesta en `ai_predictions`, actualiza el estado de la red y genera alertas si corresponde.

## Pendiente (≈20 %)

Reentrenamiento con mediciones reales acumuladas, ajuste de hiperparámetros, comparación con otros algoritmos
(One-Class SVM, LOF, autoencoder) y explicaciones con SHAP.
