"""Security audit of a home network from what the WiFiSense agent can see, scored from 0 to 100.

The audit looks for the usual weak points of a home Wi-Fi: weak or missing encryption, risky services answering on the
router (Telnet, file sharing, remote management) and devices that joined the network for the first time. Each finding
takes points off and comes with a plain-language explanation and what to do about it. Like the quality score, one
serious problem caps the result: an open network is not "acceptable" because everything else is fine.
"""
from dataclasses import dataclass

from app.schemas_security import (Authentication, FindingSeverity, SecurityFinding, SecurityGrade, SecurityRequest,
                                  SecurityResponse)

MODEL_VERSION = "security-1.0"

# The score cannot be higher than this while a finding of the given severity is present.
SEVERITY_CAP = {FindingSeverity.CRITICAL: 39, FindingSeverity.HIGH: 64}

SEVERITY_ORDER = [FindingSeverity.CRITICAL, FindingSeverity.HIGH, FindingSeverity.MEDIUM, FindingSeverity.LOW,
                  FindingSeverity.INFO]

GRADE_LABELS = {SecurityGrade.SECURE: "Segura", SecurityGrade.ACCEPTABLE: "Aceptable",
                SecurityGrade.AT_RISK: "En riesgo", SecurityGrade.CRITICAL: "Crítica"}

CONGESTED_NEIGHBORS = 4


@dataclass(frozen=True)
class Rule:
    code: str
    severity: FindingSeverity
    penalty: int
    title: str
    detail: str
    action: str

    def finding(self, **values) -> SecurityFinding:
        return SecurityFinding(code=self.code, severity=self.severity, penalty=self.penalty,
                               title=self.title.format(**values), detail=self.detail.format(**values),
                               action=self.action.format(**values))


CHANGE_TO_WPA2 = "Entra a la configuración del router y elige WPA2-AES o, si todos tus equipos lo admiten, WPA3."

ENCRYPTION_RULES = {
    Authentication.OPEN: Rule(
        "OPEN_NETWORK", FindingSeverity.CRITICAL, 60, "La red no tiene contraseña",
        "Cualquier persona cerca puede conectarse, usar tu internet y ver el tráfico que no va cifrado.",
        "Activa una contraseña larga con WPA2-AES o WPA3 en el router."),
    Authentication.WEP: Rule(
        "WEP", FindingSeverity.CRITICAL, 50, "La red usa WEP, un cifrado roto",
        "La clave WEP se descubre en pocos minutos con herramientas gratuitas.", CHANGE_TO_WPA2),
    Authentication.WPA: Rule(
        "WPA1", FindingSeverity.HIGH, 30, "La red usa WPA (primera versión)",
        "WPA tiene fallas conocidas y ya no se considera seguro.", CHANGE_TO_WPA2),
}

TKIP = Rule("TKIP", FindingSeverity.HIGH, 30, "El cifrado de la red es TKIP",
            "TKIP es el cifrado antiguo de WPA; tiene fallas conocidas y además limita la velocidad del Wi-Fi.",
            "En el router cambia el cifrado a AES (CCMP).")

UNKNOWN_AUTH = Rule("AUTH_UNKNOWN", FindingSeverity.INFO, 0, "No se pudo leer el tipo de seguridad",
                    "El agente no tiene permiso para leer los datos del Wi-Fi o el equipo está conectado por cable.",
                    "En Windows activa la ubicación para las aplicaciones de escritorio y vuelve a ejecutar el agente.")

PORT_RULES = {
    23: Rule("PORT_TELNET", FindingSeverity.HIGH, 25, "El router tiene Telnet abierto (puerto 23)",
             "Telnet envía usuario y contraseña sin cifrar y es la puerta que usan las redes de bots como Mirai.",
             "Desactiva Telnet en el router y cambia la contraseña de administración si sigue siendo la de fábrica."),
    445: Rule("PORT_SMB", FindingSeverity.HIGH, 20, "El router comparte archivos por SMB (puerto 445)",
              "SMB ha tenido fallas graves (por ejemplo la que usó WannaCry); si comparte un disco USB, cualquiera "
              "conectado al Wi-Fi puede intentar entrar.",
              "Desactiva el uso compartido de archivos o protégelo con usuario y contraseña."),
    21: Rule("PORT_FTP", FindingSeverity.MEDIUM, 15, "El router tiene FTP abierto (puerto 21)",
             "FTP envía las contraseñas sin cifrar.", "Desactiva el servidor FTP del router si no lo usas."),
    7547: Rule("PORT_TR069", FindingSeverity.MEDIUM, 10, "Gestión remota del proveedor abierta (puerto 7547)",
               "Es el canal TR-069 con el que el proveedor administra el router; ha sido atacado en el pasado.",
               "Pregunta a tu proveedor si puede limitarlo y mantén el firmware del router actualizado."),
    1900: Rule("PORT_UPNP", FindingSeverity.LOW, 5, "UPnP está activo (puerto 1900)",
               "UPnP deja que cualquier programa de la red abra puertos del router sin pedir permiso.",
               "Desactívalo si no lo necesitas para consolas o videojuegos."),
    22: Rule("PORT_SSH", FindingSeverity.LOW, 5, "El router acepta conexiones SSH (puerto 22)",
             "SSH es seguro, pero solo si la contraseña de administración es fuerte.",
             "Usa una contraseña de administración larga o desactiva SSH si no lo usas."),
}

HTTP_PORTS = {80, 8080}
HTTPS_PORTS = {443, 8443}
PLAIN_ADMIN = Rule("ADMIN_HTTP", FindingSeverity.MEDIUM, 10, "La administración del router no usa HTTPS",
                   "La página del router viaja sin cifrar: quien esté en la red puede ver la contraseña al iniciar sesión.",
                   "Activa HTTPS en la administración del router o entra a ella solo por cable.")

NEW_DEVICES = Rule("NEW_DEVICES", FindingSeverity.MEDIUM, 10, "{count} dispositivo(s) nuevo(s) en tu red",
                   "Desde el último reporte apareció {count} equipo(s) que no se habían visto antes.",
                   "Si no los reconoces, cambia la contraseña del Wi-Fi: todos tendrán que volver a conectarse.")

BAND_24 = Rule("BAND_24", FindingSeverity.INFO, 0, "Estás conectado a 2.4 GHz",
               "La banda de 2.4 GHz llega más lejos pero es más lenta y tiene más interferencia.",
               "Si estás cerca del router, conéctate a la red de 5 GHz.")

CONGESTION = Rule("CHANNEL_CONGESTION", FindingSeverity.INFO, 0, "Canal {channel} saturado",
                  "Hay {count} redes vecinas en el mismo canal y compiten por el aire con la tuya.",
                  "En el router elige otro canal (en 2.4 GHz usa 1, 6 u 11) o deja el canal en automático.")


def encryption_findings(request: SecurityRequest) -> list[SecurityFinding]:
    if request.authentication in ENCRYPTION_RULES:
        return [ENCRYPTION_RULES[request.authentication].finding()]
    if request.authentication == Authentication.UNKNOWN:
        return [UNKNOWN_AUTH.finding()]
    if request.cipher and "TKIP" in request.cipher.upper():
        return [TKIP.finding()]
    return []


def port_findings(ports: list[int]) -> list[SecurityFinding]:
    found = [PORT_RULES[port].finding() for port in ports if port in PORT_RULES]
    if HTTP_PORTS & set(ports) and not HTTPS_PORTS & set(ports):
        found.append(PLAIN_ADMIN.finding())
    return found


def environment_findings(request: SecurityRequest) -> list[SecurityFinding]:
    found = []
    if request.new_device_count:
        found.append(NEW_DEVICES.finding(count=request.new_device_count))
    if request.band == "2.4":
        found.append(BAND_24.finding())
    if request.neighbors_same_channel is not None and request.neighbors_same_channel >= CONGESTED_NEIGHBORS:
        found.append(CONGESTION.finding(channel=request.channel or "actual", count=request.neighbors_same_channel))
    return found


def grade_of(score: int) -> SecurityGrade:
    if score >= 85:
        return SecurityGrade.SECURE
    if score >= 65:
        return SecurityGrade.ACCEPTABLE
    if score >= 40:
        return SecurityGrade.AT_RISK
    return SecurityGrade.CRITICAL


def summary_of(grade: SecurityGrade, findings: list[SecurityFinding]) -> str:
    problems = [f for f in findings if f.penalty > 0]
    if not problems:
        return "No encontramos problemas de seguridad en tu red."
    worst = problems[0]
    others = len(problems) - 1
    extra = f" y {others} punto(s) más por revisar" if others else ""
    return f"Seguridad {GRADE_LABELS[grade].lower()}: lo más urgente es «{worst.title[0].lower()}{worst.title[1:]}»{extra}."


def assess(request: SecurityRequest) -> SecurityResponse:
    findings = encryption_findings(request) + port_findings(request.open_ports) + environment_findings(request)
    findings.sort(key=lambda f: (SEVERITY_ORDER.index(f.severity), -f.penalty))

    score = max(0, 100 - sum(f.penalty for f in findings))
    for finding in findings:
        score = min(score, SEVERITY_CAP.get(finding.severity, 100))
    grade = grade_of(score)
    return SecurityResponse(score=score, grade=grade, grade_label=GRADE_LABELS[grade],
                            summary=summary_of(grade, findings), findings=findings, model_version=MODEL_VERSION)
