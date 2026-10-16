"""Ventana del instalador del agente WiFiSense (tkinter, incluido en Python; no hay que instalar nada).

La persona ve qué hace el agente antes de instalarlo, escribe el código de Mi Wi-Fi y decide si arranca con
Windows. Si el agente ya está instalado, la misma ventana permite conectarlo a otra red o desinstalarlo.
"""
from __future__ import annotations

import threading
import tkinter as tk
from tkinter import messagebox, ttk

try:  # como paquete (pruebas) o como script suelto (PyInstaller)
    from agent import windows_install as setup
    from agent import wifisense_agent as agent
except ImportError:  # pragma: no cover
    import windows_install as setup
    import wifisense_agent as agent

BLUE = "#3b6cf6"
INK = "#1b2a41"
MUTED = "#6b7a90"
SKY = "#eef6fb"

EXPLANATION = (
    "El agente mide tu red Wi-Fi cada 5 minutos y envía el resultado a tu cuenta de WiFiSense:\n"
    "  • cuántos equipos están conectados y si aparece uno nuevo,\n"
    "  • la seguridad del Wi-Fi y del router,\n"
    "  • la calidad de la conexión.\n\n"
    "Las direcciones MAC de los equipos no salen de este computador. Puedes desinstalarlo cuando quieras desde "
    "Configuración > Aplicaciones."
)


class InstallerWindow:
    def __init__(self, root: tk.Tk, registry: setup.Registry, paths: setup.Paths):
        self.root = root
        self.registry = registry
        self.paths = paths
        root.title("Agente WiFiSense")
        root.configure(bg=SKY, padx=24, pady=20)
        root.resizable(False, False)
        tk.Label(root, text="Agente WiFiSense", font=("Segoe UI", 16, "bold"), fg=BLUE, bg=SKY).pack(anchor="w")
        if setup.is_installed(registry):
            self.installed_view()
        else:
            self.install_view()

    # ------------------------------------------------------------------------------------------------ vistas
    def install_view(self) -> None:
        tk.Label(self.root, text=EXPLANATION, justify="left", wraplength=440, fg=INK, bg=SKY,
                 font=("Segoe UI", 10)).pack(anchor="w", pady=(8, 14))
        tk.Label(self.root, text="Código de instalación (Mi Wi-Fi > Agente WiFiSense > Instalar agente)",
                 fg=INK, bg=SKY, font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.code = tk.StringVar()
        entry = ttk.Entry(self.root, textvariable=self.code, font=("Consolas", 16), width=14, justify="center")
        entry.pack(anchor="w", pady=(4, 10))
        entry.focus_set()
        self.autostart = tk.BooleanVar(value=True)
        ttk.Checkbutton(self.root, text="Iniciar el agente automáticamente al encender el computador",
                        variable=self.autostart).pack(anchor="w")
        self.status = tk.Label(self.root, text="", fg=MUTED, bg=SKY, wraplength=440, justify="left")
        self.status.pack(anchor="w", pady=(10, 4))
        buttons = tk.Frame(self.root, bg=SKY)
        buttons.pack(anchor="e", pady=(6, 0))
        ttk.Button(buttons, text="Cancelar", command=self.root.destroy).pack(side="right", padx=(8, 0))
        self.install_button = ttk.Button(buttons, text="Instalar", command=self.install)
        self.install_button.pack(side="right")
        self.root.bind("<Return>", lambda _event: self.install())

    def installed_view(self) -> None:
        config = agent.load_config()
        network = config.get("network") or "tu red"
        auto = "arranca con Windows" if setup.starts_with_windows(self.registry) else "no arranca solo con Windows"
        tk.Label(self.root, text=f"El agente está instalado y envía los reportes de «{network}» ({auto}).",
                 fg=INK, bg=SKY, wraplength=440, justify="left", font=("Segoe UI", 10)).pack(anchor="w", pady=12)
        buttons = tk.Frame(self.root, bg=SKY)
        buttons.pack(anchor="e")
        ttk.Button(buttons, text="Cerrar", command=self.root.destroy).pack(side="right", padx=(8, 0))
        ttk.Button(buttons, text="Desinstalar", command=self.uninstall).pack(side="right", padx=(8, 0))
        ttk.Button(buttons, text="Usar otro código", command=self.reinstall).pack(side="right")

    # ----------------------------------------------------------------------------------------------- acciones
    def install(self) -> None:
        code = agent.normalize_code(self.code.get())
        if not code:
            self.say("El código tiene 8 letras y números, por ejemplo K7QM-4RZD.", error=True)
            return
        self.install_button.state(["disabled"])
        self.say("Conectando con WiFiSense…")
        threading.Thread(target=self._install, args=(code, self.autostart.get()), daemon=True).start()

    def _install(self, code: str, autostart: bool) -> None:
        try:
            server = agent.load_config()["server"]
            answer = agent.pair(code, server)
            agent.save_pairing(answer, server)
            setup.stop_running_agent(self.paths)  # un agente anterior puede estar corriendo desde la carpeta que se reemplaza
            exe = setup.install(setup.current_executable(), self.paths, self.registry, agent.AGENT_VERSION, autostart)
            setup.start_agent(self.paths)
        except agent.SendError as error:
            self.root.after(0, self._failed, f"No se pudo instalar: {error}.")
            return
        except OSError as error:
            self.root.after(0, self._failed, f"No se pudo copiar el programa: {error}.")
            return
        network = answer.get("networkName") or "tu red"
        self.root.after(0, self._done, network, exe)

    def _failed(self, message: str) -> None:
        self.say(message, error=True)
        self.install_button.state(["!disabled"])

    def _done(self, network: str, exe) -> None:
        messagebox.showinfo("Agente WiFiSense", f"Listo. El agente ya está midiendo «{network}» y en un momento "
                            "verás los datos en Mi Wi-Fi.\n\nPuedes cerrar esta ventana.")
        self.root.destroy()

    def reinstall(self) -> None:
        for widget in self.root.winfo_children()[1:]:
            widget.destroy()
        self.install_view()

    def uninstall(self) -> None:
        if not messagebox.askyesno("Agente WiFiSense", "¿Desinstalar el agente? Dejará de enviar reportes y se borrará "
                                                       "su clave de este computador."):
            return
        setup.uninstall(self.paths, self.registry)
        messagebox.showinfo("Agente WiFiSense", "El agente se desinstaló.")
        self.root.destroy()

    def say(self, text: str, error: bool = False) -> None:
        self.status.configure(text=text, fg="#c8323c" if error else MUTED)


def open_installer() -> None:
    root = tk.Tk()
    InstallerWindow(root, setup.WindowsRegistry(), setup.Paths.for_user())
    root.mainloop()


def confirm_uninstall() -> None:
    """Lo que ejecuta Windows al elegir Desinstalar en Configuración > Aplicaciones."""
    root = tk.Tk()
    root.withdraw()
    if messagebox.askyesno("Agente WiFiSense", "¿Desinstalar el agente WiFiSense? Dejará de enviar reportes y se "
                                               "borrará su clave de este computador."):
        setup.uninstall(setup.Paths.for_user(), setup.WindowsRegistry())
        messagebox.showinfo("Agente WiFiSense", "El agente se desinstaló.")
    root.destroy()
