# Auditoría de seguridad (`security-1.0`)

La auditoría usa lo que el agente WiFiSense puede ver desde un equipo de la casa, sin instalar nada en el router y
sin atacar nada: el tipo de seguridad del Wi-Fi que informa el sistema operativo, qué puertos TCP del router responden
a una conexión (sin enviar datos), cuántos equipos responden en la red y cuáles no se habían visto antes.

Es un sistema de reglas, no un modelo entrenado: cada regla corresponde a una debilidad conocida y documentada, y así
cada punto que se resta se puede explicar al usuario.

## Reglas

| Código | Qué se detecta | Gravedad | Resta |
|---|---|---|---|
| `OPEN_NETWORK` | Wi-Fi sin contraseña | Crítica | 60 |
| `WEP` | Cifrado WEP (se rompe en minutos) | Crítica | 50 |
| `WPA1` | WPA de primera versión | Alta | 30 |
| `TKIP` | WPA2 con cifrado TKIP en lugar de AES | Alta | 30 |
| `PORT_TELNET` | Puerto 23 abierto en el router | Alta | 25 |
| `PORT_SMB` | Puerto 445 (archivos compartidos) | Alta | 20 |
| `PORT_FTP` | Puerto 21 | Media | 15 |
| `PORT_TR069` | Puerto 7547 (gestión remota del proveedor) | Media | 10 |
| `ADMIN_HTTP` | Página del router por HTTP (80/8080) sin HTTPS (443/8443) | Media | 10 |
| `NEW_DEVICES` | Equipos que no estaban en el reporte anterior | Media | 10 |
| `PORT_UPNP` | Puerto 1900 (UPnP) | Baja | 5 |
| `PORT_SSH` | Puerto 22 | Baja | 5 |
| `AUTH_UNKNOWN` | El agente no pudo leer el tipo de seguridad | Informativa | 0 |
| `BAND_24` | Conexión en 2.4 GHz | Informativa | 0 |
| `CHANNEL_CONGESTION` | 4 o más redes vecinas en el mismo canal | Informativa | 0 |

## Puntaje

`puntaje = max(0, 100 − suma de lo que resta cada hallazgo)`, con dos topes: si hay un hallazgo crítico el puntaje
queda en 39 o menos, y si hay uno alto en 64 o menos. Sin los topes, una red abierta con todo lo demás bien sacaría
40 y quedaría "En riesgo" en lugar de "Crítica".

Los hallazgos se ordenan de más a menos grave y el resumen nombra el más urgente.

## Límites

- Solo se revisan los puertos que el agente prueba (21, 22, 23, 53, 80, 443, 445, 1900, 7547, 8080, 8443); no es un
  escaneo completo.
- UPnP usa normalmente UDP; el agente solo detecta los routers que además lo exponen por TCP.
- Un equipo "nuevo" puede ser uno conocido que cambió su MAC (los celulares lo hacen por privacidad).
- No se puede saber si la contraseña del Wi-Fi o la del router son débiles: eso queda como recomendación general.
