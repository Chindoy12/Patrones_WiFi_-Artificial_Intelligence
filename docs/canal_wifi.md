# Recomendación del mejor canal Wi-Fi

`app/channel.py` · `POST /api/v1/channel/recommend` · versión `channel-1.0`

## Qué recibe

El agente WiFiSense lee las redes que el sistema ve alrededor (`netsh wlan show networks mode=bssid` en Windows,
`nmcli dev wifi list` en Linux) y envía, sin contar los puntos de acceso de la propia red, cuántos hay en cada canal:

```json
{"band": "2.4", "channel": 6, "channelCounts": [{"channel": 1, "networks": 3}, {"channel": 6, "networks": 4}]}
```

## Cómo decide

1. **Banda.** La del reporte o, si falta, la del canal (1–14 → 2,4 GHz; 32–177 → 5 GHz). Los vecinos de la otra
   banda no cuentan.
2. **Canales candidatos.** En 2,4 GHz solo 1, 6 y 11 (los únicos que no se encima). En 5 GHz los que no usan radar
   (36–48 y 149–165), que todo equipo admite.
3. **Interferencia (`load`)** de cada candidato = Σ vecinos × encimamiento:

   | Caso | Encimamiento |
   |---|---|
   | Mismo canal | 1 |
   | 2,4 GHz a *d* canales de distancia | max(0, 1 − d/5) |
   | 5 GHz en el mismo bloque de 80 MHz | 0,5 |
   | Otro caso | 0 |

4. **Mejor canal:** el de menor interferencia; en empate gana el actual (no hay por qué moverse) y luego el menor.
5. **¿Cambiar?** Solo si el mejor tiene al menos **1** de interferencia menos que el actual (una red vecina entera),
   o si el router está en un canal de 2,4 GHz fuera de 1/6/11 y existe uno mejor. Cambiar de canal desconecta todos
   los equipos unos segundos, así que no se recomienda por diferencias pequeñas.

## Casos especiales

- **Sin `channelCounts`** (el agente no pudo leer las redes vecinas, por ejemplo sin permiso de ubicación en Windows):
  no hay recomendación y se explica por qué.
- **6 GHz:** no se compara. Sus números de canal repiten los de las otras bandas, así que con los conteos del agente
  no se pueden distinguir, y en la práctica casi no hay vecinos en esa banda.
- **Canal actual desconocido:** se dice cuál es el más tranquilo, sin decir que hay que cambiar.

## Ejemplo

Router en el canal 6 con 4 vecinos en el 6 y 3 en el 1: interferencia 6 → 4, 1 → 3, 11 → 0. Se recomienda el 11
porque la mejora (4) supera el mínimo (1).
