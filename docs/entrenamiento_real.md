# Entrenamiento con mediciones reales

Hasta el Avance 15 el modelo de anomalías se entrenaba solo con una línea base **sintética** (5 000 mediciones
simuladas de redes sanas). Desde el Avance 16 se puede entrenar con las **mediciones reales** que toman los sensores
de las redes del equipo y los agentes de Mi Wi-Fi.

## De dónde salen los datos

El servicio de IA no tiene acceso a la base de datos (el backend es el único intermediario), así que el backend arma
el conjunto y lo envía a `POST /api/v1/model/train`:

| Origen | Variables |
|---|---|
| Sensores de las redes del equipo (`measurements` con fuente `AGENT`, cruzadas con `traffic_observations`) | latencia, jitter, pérdida, señal, equipos, tráfico y paquetes |
| Agentes de Mi Wi-Fi (`agent_reports`) | latencia, jitter, pérdida, señal y equipos |

Se usan los últimos 30 días, como máximo las 10 000 mediciones más recientes. Las mediciones simuladas nunca se usan.
Solo viajan y se guardan los números: ni la red, ni el usuario, ni los equipos. Una variable que nadie midió (por
ejemplo el ancho de banda, o la señal de un computador por cable) se completa con la mediana de los datos reales o,
si no hay ninguna, con la de la línea base sintética.

## Cómo se decide si el modelo nuevo es mejor

Todavía no hay fallas reales etiquetadas, así que la prueba se arma con los mismos datos reales:

1. Las mediciones se ordenan por tiempo. El **80 % más antiguo** entrena el modelo candidato.
2. El **20 % más reciente** queda aparte como prueba **normal**: un buen modelo da pocas falsas alarmas con el
   comportamiento real de estas redes.
3. Una copia de ese 20 % se degrada con las cinco fallas simuladas (congestión, interferencia, cobertura débil,
   falla del proveedor y tráfico sospechoso, con intensidad aleatoria) como prueba de **fallas**: un buen modelo las
   sigue encontrando.
4. El candidato y el modelo en uso se miden sobre exactamente la misma prueba (precisión, recall, F1 y tasa de falsas
   alarmas).

El candidato reemplaza al modelo en uso si:

- encuentra claramente mejor las fallas (F1 al menos 0,02 más alto), **o**
- las encuentra igual de bien (F1 a lo sumo 0,02 más bajo) y da **menos falsas alarmas**.

Si no, se rechaza y se sigue usando el actual. La razón queda escrita en español. Cuando se aprueba, el modelo que se
pone en uso se entrena con **todas** las mediciones (no solo el 80 %), con la misma semilla.

Lo esperable: el modelo sintético supone redes de unos 20 ms; una red real con 40–50 ms le parece anómala todo el
tiempo. El modelo real aprende cómo son estas redes y da muchas menos falsas alarmas, sin dejar de ver las fallas.

## Versiones e historial

Cada entrenamiento queda en la tabla `ai_model_versions` (WiFiSense-database V38): nombre de la versión
(`real-AAAAMMDD-HHmm`), cuántas mediciones y de cuántas redes, el periodo, las métricas de los dos modelos, la decisión
(`PROMOTED` o `REJECTED`), la razón y cuál está activo (como mucho uno). La página **Modelo IA** lo muestra y un
administrador puede pedir **Entrenar ahora**. El backend entrena solo cada lunes a las 3:00 (hora de Colombia).

## Después de un redespliegue

Railway borra el disco del servicio de IA al redesplegarlo, y la IA arranca con el modelo sintético. Cada 10 minutos el
backend pregunta qué versión usa la IA (`GET /api/v1/model`); si no es la activa, le envía las mismas mediciones
guardadas en `training_set` con `restore: true` y la IA reconstruye exactamente el mismo modelo, sin evaluarlo otra
vez. Mientras tanto la detección sigue funcionando con el modelo sintético.

## Límites honestos

- Las fallas de la prueba son simuladas sobre datos reales; cuando el equipo marque fallas reales se podrán medir con
  ellas.
- Si una red tuvo muchos problemas durante el periodo, el modelo aprende parte de eso como "normal". Por eso se exige
  un mínimo de 300 mediciones (unas 25 horas de un sensor) y se recomienda entrenar con varios días de varias redes.
