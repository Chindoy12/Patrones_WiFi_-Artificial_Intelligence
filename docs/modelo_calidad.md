# Modelo de calidad de la conexión (quality-1.0)

Califica una conexión de 0 a 100 a partir de lo que se pudo medir. Lo usan el panel del equipo (salud de cada red
con su última medición) y Mi Wi-Fi (prueba de conexión del usuario final). Es un **modelo experto**: no se entrena
con datos, se construye con los requisitos conocidos de cada servicio, así que cada puntaje se puede explicar.

## Curvas por métrica

Entre dos puntos el puntaje se interpola en línea recta; fuera de ellos toma el valor del extremo.

| Métrica | Puntos (valor → puntaje) | Por qué |
|---|---|---|
| Latencia (ms) | 20 → 100 · 50 → 85 · 100 → 60 · 200 → 30 · 400 → 0 | Bajo 150 ms una llamada se siente natural; los juegos piden menos de 60 ms |
| Jitter (ms) | 5 → 100 · 15 → 80 · 30 → 55 · 60 → 25 · 100 → 0 | Sobre 30 ms la voz y el video se entrecortan |
| Pérdida (%) | 0 → 100 · 0,5 → 90 · 1 → 75 · 3 → 45 · 5 → 25 · 10 → 0 | Desde 1 % se nota en llamadas y juegos |
| Bajada (Mbps) | 1 → 5 · 5 → 30 · 10 → 50 · 25 → 75 · 50 → 90 · 100 → 100 | 5 Mbps alcanzan para video HD y 25 Mbps para 4K |
| Bajada / contratada | 10 % → 10 · 30 % → 40 · 50 % → 65 · 70 % → 85 · 90 % → 100 | Por Wi-Fi es normal recibir algo menos de lo contratado |
| Subida (Mbps) | 0,5 → 5 · 2 → 30 · 5 → 50 · 10 → 70 · 20 → 85 · 50 → 100 | Una videollamada HD necesita unos 3 Mbps de subida |
| Señal (dBm) | −90 → 0 · −85 → 15 · −75 → 45 · −67 → 75 · −60 → 90 · −50 → 100 | −67 dBm es el mínimo usual para voz y video estables |

## Puntaje total

Promedio ponderado de las métricas medidas (latencia 25 %, bajada 25 %, pérdida 20 %, jitter 15 %, subida 10 %,
señal 5 %; los pesos se reparten entre las que existan). Luego se limita a **la peor métrica + 30**: una conexión
muy rápida pero que pierde el 12 % de los paquetes no puede salir "buena".

## Actividades

| Actividad | Necesita |
|---|---|
| Navegar y correo | bajada ≥ 1 Mbps, latencia ≤ 300 ms, pérdida ≤ 5 % |
| Videollamadas y clases | bajada y subida ≥ 3 Mbps, latencia ≤ 150 ms, jitter ≤ 30 ms, pérdida ≤ 2 % |
| Video en HD | bajada ≥ 5 Mbps, pérdida ≤ 3 % |
| Video en 4K | bajada ≥ 25 Mbps, pérdida ≤ 2 % |
| Juegos en línea | latencia ≤ 60 ms, jitter ≤ 20 ms, pérdida ≤ 1 % |

Si falta la bajada, la subida, la latencia o el jitter que la actividad necesita, la respuesta dice `null` (no se
sabe) en vez de adivinar. La pérdida de paquetes se exige solo cuando se midió: la prueba del navegador no puede
medirla (el agente sí), y sin esta regla ninguna prueba de Mi Wi-Fi podría decir para qué alcanza la conexión.

## Límites

- La prueba del navegador mide la conexión **hasta el servidor de WiFiSense**: incluye el Wi-Fi y el camino por
  internet. La señal Wi-Fi, el canal o los dispositivos conectados solo los puede medir el agente.
- Los puntos de las curvas son una decisión de diseño explicada arriba; cuando haya datos reales se podrán ajustar.
