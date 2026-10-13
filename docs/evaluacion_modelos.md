# Evaluación de modelos (isolation-forest-1.1)

Generado con `python -m app.evaluation`; el servicio calcula el mismo informe al arrancar y lo entrega en
`GET /api/v1/model/evaluation`. Los tiempos se midieron en el equipo de desarrollo y cambian según la máquina.

Escenarios sintéticos etiquetados: redes sanas más cinco fallas simuladas (congestión, interferencia, cobertura débil, falla del proveedor y tráfico sospechoso) con intensidad aleatoria. No son datos reales; la evaluación se repetirá con mediciones del agente.

Entrenamiento: 5000 mediciones sanas. Prueba: 2000 sanas y 500 con falla.

## Comparación de algoritmos

| Algoritmo | Precisión | Recall | F1 | Falsos positivos | ROC-AUC | Entrenar | Predecir/medición |
|---|---|---|---|---|---|---|---|
| **IsolationForest** (producción) | 91.8 % | 87.8 % | 0.898 | 1.9 % | 0.978 | 655 ms | 22.2 µs |
| LocalOutlierFactor | 92.2 % | 87.4 % | 0.897 | 1.8 % | 0.977 | 273 ms | 50.9 µs |
| OneClassSVM | 87.4 % | 90.0 % | 0.887 | 3.2 % | 0.977 | 41 ms | 6.0 µs |

## Recall por tipo de falla

| Algoritmo | CONGESTION | INTERFERENCE | WEAK_COVERAGE | PROVIDER_ISSUE | SUSPICIOUS_TRAFFIC |
|---|---|---|---|---|---|
| IsolationForest | 99.0 % | 100.0 % | 95.0 % | 77.0 % | 68.0 % |
| LocalOutlierFactor | 99.0 % | 100.0 % | 80.0 % | 82.0 % | 76.0 % |
| OneClassSVM | 99.0 % | 100.0 % | 94.0 % | 84.0 % | 73.0 % |

## Ajuste de Isolation Forest (conjunto de validación)

| Árboles | Muestras por árbol | F1 | Recall | Falsos positivos |
|---|---|---|---|---|
| 200 | 256 | 0.803 | 72.6 % | 2.1 % |
| 500 | 256 | 0.824 | 75.6 % | 2.0 % |
| 200 | 1024 | 0.849 | 79.4 % | 1.9 % |
| 500 | 1024 | 0.861 | 81.4 % | 1.9 % |
| 200 | todas (5000) | 0.892 ✔ | 86.4 % | 1.8 % |
| 500 | todas (5000) | 0.880 | 86.0 % | 2.4 % |

## Sensibilidad del umbral (contaminación)

| Contaminación | Precisión | Recall | Falsos positivos |
|---|---|---|---|
| 0.01 | 96.0 % | 81.6 % | 0.9 % |
| 0.02 (producción) | 91.8 % | 87.8 % | 1.9 % |
| 0.05 | 81.8 % | 92.4 % | 5.1 % |
| 0.10 | 69.6 % | 94.4 % | 10.3 % |

## Diagnóstico de la causa

Acierto: 94.3 % sobre 439 fallas detectadas.

## Conclusiones

- **Los tres algoritmos quedan muy cerca** (F1 entre 0,887 y 0,898 y ROC-AUC ≈ 0,977), así que la elección no
  depende solo de la precisión.
- **Isolation Forest sigue en producción:** obtiene el mejor F1 en este conjunto, mantiene las falsas alarmas cerca
  del 2 % configurado, no necesita escalar las variables y su resultado se explica con las desviaciones por variable.
  Además predice en menos de la mitad del tiempo de LOF.
- **One-Class SVM** detecta un poco más (recall 90 %), pero a cambio de más falsas alarmas (3,2 %). **LOF** pierde
  bastante en cobertura débil (80 %).
- **Ajuste de hiperparámetros:** que cada árbol use toda la línea base en vez de 256 muestras subió el F1 de
  validación de 0,80 a 0,89. Se eligió en un conjunto de validación distinto al de prueba para no ajustar el modelo a
  sus propios resultados.
- **Umbral:** con 2 % de contaminación se detecta el 88 % de las fallas con 1,9 % de falsas alarmas. Subirlo a 5 %
  detecta más (92 %), pero casi triplica las alarmas falsas, que en un panel de monitoreo cansan al equipo.
- **Punto débil:** las fallas suaves del proveedor y el tráfico sospechoso leve son las más difíciles (77 % y 68 %).
  Se mejorarán con mediciones reales del agente y con variables que separen la red local de internet (por ejemplo,
  la latencia al router frente a la latencia a internet).
- **Diagnóstico:** de las fallas detectadas, el 94 % recibe la causa correcta con las firmas de `app/diagnosis.py`.

## Limitaciones

Todos los datos son simulados: los escenarios imitan cómo cada falla degrada una red, pero no reemplazan
mediciones reales etiquetadas. Cuando el agente recolecte datos reales, esta evaluación se repetirá con ellos.
