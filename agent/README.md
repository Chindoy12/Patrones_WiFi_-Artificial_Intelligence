# Agente WiFiSense

Programa que corre en un computador de tu casa, mide la red Wi-Fi y envía un reporte a WiFiSense cada 5 minutos.
Con esos reportes la IA te dice **cuántos equipos están conectados**, si apareció uno nuevo, qué tan segura es tu red
(auditoría de seguridad) y si hay anomalías en la conexión.

## Instalación en Windows (sin Python)

1. En WiFiSense entra a **Mi Wi-Fi → Agente WiFiSense → Instalar agente**. La página muestra un código de 8
   caracteres (sirve 15 minutos y una sola vez) y el botón **Descargar instalador**.
2. Abre `WiFiSenseAgente.exe`. Como es un programa nuevo sin firma digital, Windows puede mostrar «Windows protegió
   su PC»: pulsa **Más información → Ejecutar de todas formas**.
3. La ventana explica qué hace el agente. Escribe el código, deja marcada (o no) la opción de iniciar con Windows y
   pulsa **Instalar**. En segundos aparecen los datos en Mi Wi-Fi.

Qué queda en el computador, todo a la vista y para el usuario actual (no pide permisos de administrador):

| Dónde | Qué |
|---|---|
| `%LOCALAPPDATA%\Programs\WiFiSense\WiFiSenseAgente.exe` | El programa |
| `%APPDATA%\WiFiSense\agent.json` | La clave del agente y la sal de las huellas (solo para tu usuario) |
| `%LOCALAPPDATA%\WiFiSense\agente.log` | Lo que hace el agente en segundo plano (máximo 1 MB) |
| Administrador de tareas → Aplicaciones de inicio | «WiFiSenseAgente», si elegiste iniciar con Windows (se puede desactivar ahí) |
| Configuración → Aplicaciones → Aplicaciones instaladas | «Agente WiFiSense» con **Desinstalar**, que borra todo lo anterior |

El instalador se construye en GitHub Actions (`.github/workflows/agente-windows.yml`, PyInstaller) cada vez que
cambia la carpeta `agent/` en `main`, y se publica en la versión `agente` del repositorio.

## Uso con Python (Windows o Linux)

Solo necesita **Python 3.9 o superior** (en Windows: Microsoft Store → "Python 3.12"). No instala nada más.

1. En WiFiSense entra a **Mi Wi-Fi → Agente WiFiSense → Instalar agente** y anota el código.
2. Descarga `wifisense_agent.py` (opción «Usar con Python» de esa pantalla).
3. En CMD, en la carpeta donde lo descargaste:

```cmd
python wifisense_agent.py pair K7QM-4RZD
python wifisense_agent.py scan
python wifisense_agent.py run
```

`pair` cambia el código por la clave del agente y la guarda. También sigue funcionando `setup`, que pide la clave
larga (Mi Wi-Fi → Crear clave) sin mostrarla y la guarda solo para tu usuario (`%APPDATA%\WiFiSense\agent.json` en Windows,
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
