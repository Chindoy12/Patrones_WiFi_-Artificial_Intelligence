"""Install (or reinstall) the agent with a code: what the Install button of the window does, without the window."""
from __future__ import annotations

try:  # como paquete (pruebas) o como script suelto (PyInstaller)
    from agent import windows_install as setup
    from agent import wifisense_agent as agent
except ImportError:  # pragma: no cover
    import windows_install as setup
    import wifisense_agent as agent


def install_and_pair(code: str, autostart: bool, paths, registry, pair=None, stop=None, copy_in=None, start=None):
    """
    Installs the program and then exchanges the code. The order matters: the code works once, so it is used only
    after the program is in place. Earlier versions used it first, and when Windows refused to replace a running agent
    the code was already spent ("El código no es válido o ya venció" on the next try). If the code is refused, an agent
    that was already installed goes on measuring its network. Returns (network, exe), or the message to show.
    """
    pair = pair or agent.pair
    stop = stop or setup.stop_running_agent
    copy_in = copy_in or (lambda: setup.install(setup.current_executable(), paths, registry, agent.AGENT_VERSION,
                                                autostart))
    start = start or setup.start_agent
    config = agent.load_config()
    had_agent = bool(config.get("key"))
    stop(paths)
    try:
        exe = copy_in()
    except OSError as error:
        if had_agent and paths.exe.exists():
            start(paths)
        return (f"No se pudo copiar el programa: {error}. Cierra «WiFiSenseAgente.exe» en el Administrador de tareas "
                "y vuelve a pulsar Instalar: el código no se gastó.")
    try:
        answer = pair(code, config["server"])
        agent.save_pairing(answer, config["server"])
    except agent.SendError as error:
        if had_agent:
            start(paths)
        return f"No se pudo instalar: {error}."
    start(paths)
    return answer.get("networkName") or "tu red", exe
