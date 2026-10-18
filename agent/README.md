# Agente WiFiSense

Programa que corre en un computador de tu casa, mide la red Wi-Fi y envía un reporte a WiFiSense cada 5 minutos.
Con esos reportes la IA te dice **cuántos equipos están conectados**, si apareció uno nuevo, qué tan segura es tu red
(auditoría de seguridad) y si hay anomalías en la conexión.

El mismo programa es el **sensor de las redes del equipo**: en el panel, **Redes → (la red) → Conectar sensor** muestra
un código de 8 caracteres; se instala igual, en un computador conectado a esa red, y desde entonces sus reportes son
las mediciones reales de esa red (latencia, pérdida, señal, velocidad del enlace, equipos y tráfico). Desde 1.5.0 el
panel muestra además, como Mi Wi-Fi, los equipos conectados (fabricante y nombre), la auditoría de seguridad y el mejor
canal. El código decide para cuál red trabaja: uno de Mi Wi-Fi la conecta con la casa del usuario; uno del panel, con
la red del equipo. Un computador mide una sola red (la del Wi-Fi al que está conectado): un código nuevo lo cambia de
red.

## Instalación en Windows (sin Python)

1. En WiFiSense entra a **Mi Wi-Fi → Agente WiFiSense → Instalar agente**. La página muestra un código de 8
   caracteres (sirve 15 minutos y una sola vez) y el botón **Descargar instalador**.
2. Abre `WiFiSenseAgente.exe`. Como es un programa nuevo sin firma digital, Windows puede mostrar «Windows protegió
   su PC»: pulsa **Más información → Ejecutar de todas formas**.
3. La ventana explica qué hace el agente. Escribe el código, deja marcada (o no) la opción de iniciar con Windows y
   pulsa **Instalar**. En segundos aparecen los datos en Mi Wi-Fi (o en el panel del sensor).
4. Para pasarlo a otra red no hay que descargarlo otra vez: abre el mismo programa, pulsa **Usar otro código** y
   escribe el código nuevo.

**Reinstalar con el agente en marcha (1.5.0).** El programa de PyInstaller corre como dos procesos y los dos
mantienen abierto el `.exe`; hasta 1.4.0 el instalador detenía solo uno y Windows no dejaba reemplazar el programa
(«WinError 32 … está siendo utilizado por otro proceso»). Además gastaba el código antes de copiar, así que el
siguiente intento decía «El código no es válido o ya venció». Ahora detiene todos los procesos que corren desde el
programa instalado (nunca el propio instalador), espera a que Windows suelte el archivo, copia y solo entonces usa el
código. Si algo falla, el agente que ya estaba sigue midiendo su red.

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

## Uso con Python (desarrollo o Linux)

La página de WiFiSense solo ofrece el instalador de Windows, para que nadie tenga que abrir CMD. El script sigue
siendo el mismo agente (el instalador se construye a partir de él) y se puede usar directo, por ejemplo en Linux o
para probar cambios. Solo necesita **Python 3.9 o superior**; no instala nada más.

1. En WiFiSense entra a **Mi Wi-Fi → Agente WiFiSense → Instalar el agente** y anota el código.
2. Descarga `agent/wifisense_agent.py` de este repositorio.
3. En la carpeta donde lo descargaste:

```cmd
python wifisense_agent.py pair K7QM-4RZD
python wifisense_agent.py scan
python wifisense_agent.py run
```

`pair` cambia el código por la clave del agente y la guarda solo para tu usuario (`%APPDATA%\WiFiSense\agent.json` en Windows,
`~/.config/WiFiSense/agent.json` en Linux). `scan` mide y muestra exactamente lo que se enviaría, sin enviar nada.
`run` envía un reporte cada 5 minutos hasta que pulses Ctrl + C (`run --once` envía uno solo).

Si Windows no deja leer los datos del Wi-Fi: Configuración → Privacidad y seguridad → Ubicación → activa
"Permitir que las aplicaciones de escritorio accedan a tu ubicación" (Windows 11 lo exige para `netsh wlan`).

## Qué mide

| Dato | Cómo |
|---|---|
| Nombre de la red, seguridad, cifrado, señal, canal, banda | `netsh wlan show interfaces` (Windows) o `nmcli` (Linux) |
| Redes vecinas por canal (para recomendar el mejor) | `netsh wlan show networks mode=bssid` o `nmcli` |
| Latencia, jitter y pérdida hacia internet | 10 conexiones TCP a 1.1.1.1:443 |
| Latencia hacia el router | 5 conexiones TCP al router |
| Equipos conectados | un datagrama vacío a cada dirección de la red para llenar la tabla ARP y luego `arp -a` |
| Fabricante de cada equipo | primeros 3 bytes de la MAC (OUI) en una tabla de ~180 fabricantes comunes |
| Nombre de cada equipo | DNS inverso, NetBIOS (Windows) y mDNS/Bonjour (iPhone, Mac, Chromecast, impresoras) |
| MAC privada | bit de «administración local»: celulares y tabletas que usan una MAC aleatoria en cada red |
| Puertos abiertos en el router | intento de conexión a 21, 22, 23, 53, 80, 443, 445, 1900, 7547, 8080 y 8443 |
| Tráfico de este computador (desde 1.4.0) | contadores del sistema desde el reporte anterior: bytes y paquetes de la tarjeta Wi-Fi (o de cable) y paquetes TCP, UDP e ICMP. En Windows con la API IP Helper (`GetIfTable2`, `GetTcpStatisticsEx`…), igual en cualquier idioma; en Linux de `/proc/net/dev` y `/proc/net/snmp`. No se instala ningún programa de captura |

## Privacidad y seguridad

- Las direcciones MAC **no salen del computador**: se envía una huella SHA-256 con una sal aleatoria creada en esta
  instalación. Sirve para saber si un equipo es nuevo, pero no para saber cuál es.
- De cada equipo se envía el fabricante y el nombre que **él mismo anuncia** en la red (como en la lista de
  Bluetooth), para que lo reconozcas. No se envían IP ni el nombre del usuario del computador.
- La clave solo viaja por HTTPS (el agente rechaza `http://` salvo `localhost`, para pruebas). En el servidor se
  guarda solo su SHA-256; si la pierdes o se filtra, revócala en Mi Wi-Fi → Agente y crea otra.
- El agente no ataca ni cambia nada: solo lee datos del sistema e intenta conexiones normales.
- Del tráfico solo se envían **totales** (cuántos bytes y paquetes, y de qué protocolo), nunca a dónde ni qué
  contenía. Es el tráfico de ese computador, no el de toda la red (eso solo lo ve el router), y solo se guarda cuando
  el agente es el sensor de una red del equipo. Los contadores del último envío quedan en
  `%APPDATA%\WiFiSense\traffic.json`.

Variables opcionales: `WIFISENSE_AGENT_KEY` y `WIFISENSE_SERVER` reemplazan lo guardado por `pair` (o por `setup`, que acepta una clave larga de versiones anteriores).
