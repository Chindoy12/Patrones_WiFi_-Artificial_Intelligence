# Agente WiFiSense

Programa que corre en un computador de tu casa, mide la red Wi-Fi y envía un reporte a WiFiSense cada 5 minutos.
Con esos reportes la IA te dice **cuántos equipos están conectados**, si apareció uno nuevo, qué tan segura es tu red
(auditoría de seguridad) y si hay anomalías en la conexión.

Solo necesita **Python 3.9 o superior** (en Windows: Microsoft Store → "Python 3.12"). No instala nada más.

## Uso

1. En WiFiSense entra a **Mi Wi-Fi → Agente** y pulsa **Crear clave**. Cópiala: solo se muestra una vez.
2. Descarga `wifisense_agent.py` desde esa misma pantalla.
3. En CMD, en la carpeta donde lo descargaste:

```cmd
python wifisense_agent.py setup
python wifisense_agent.py scan
python wifisense_agent.py run
```

`setup` pide la clave sin mostrarla y la guarda solo para tu usuario (`%APPDATA%\WiFiSense\agent.json` en Windows,
`~/.config/WiFiSense/agent.json` en Linux). `scan` mide y muestra exactamente lo que se enviaría, sin enviar nada.
`run` envía un reporte cada 5 minutos hasta que pulses Ctrl + C (`run --once` envía uno solo).

Si Windows no deja leer los datos del Wi-Fi: Configuración → Privacidad y seguridad → Ubicación → activa
"Permitir que las aplicaciones de escritorio accedan a tu ubicación" (Windows 11 lo exige para `netsh wlan`).

## Qué mide

| Dato | Cómo |
|---|---|
| Nombre de la red, seguridad, cifrado, señal, canal, banda | `netsh wlan show interfaces` (Windows) o `nmcli` (Linux) |
| Redes vecinas en tu canal | `netsh wlan show networks mode=bssid` o `nmcli` |
| Latencia, jitter y pérdida hacia internet | 10 conexiones TCP a 1.1.1.1:443 |
| Latencia hacia el router | 5 conexiones TCP al router |
| Equipos conectados | un datagrama vacío a cada dirección de la red para llenar la tabla ARP y luego `arp -a` |
| Puertos abiertos en el router | intento de conexión a 21, 22, 23, 53, 80, 443, 445, 1900, 7547, 8080 y 8443 |

## Privacidad y seguridad

- Las direcciones MAC **no salen del computador**: se envía una huella SHA-256 con una sal aleatoria creada en esta
  instalación. Sirve para saber si un equipo es nuevo, pero no para saber cuál es.
- No se envían nombres de equipos, IP, ni el nombre del usuario del computador.
- La clave solo viaja por HTTPS (el agente rechaza `http://` salvo `localhost`, para pruebas). En el servidor se
  guarda solo su SHA-256; si la pierdes o se filtra, revócala en Mi Wi-Fi → Agente y crea otra.
- El agente no ataca ni cambia nada: solo lee datos del sistema e intenta conexiones normales.

Variables opcionales: `WIFISENSE_AGENT_KEY` y `WIFISENSE_SERVER` reemplazan lo guardado por `setup`.
