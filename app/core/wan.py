# app/core/wan.py

import subprocess
import json
import os
from typing import Dict, Any, Tuple, Optional
from ..utils.global_functions import create_module_config_directory, create_module_log_directory

# Config file in V4 structure
CONFIG_FILE = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "config", "wan", "wan.json")
)

# -----------------------------
# Utilidades internas
# -----------------------------

def _run_command(cmd: list) -> Tuple[bool, str]:
    """Ejecutar comando con sudo automáticamente."""
    try:
        full_cmd = ["sudo"] + cmd
        result = subprocess.run(
            full_cmd,
            capture_output=True,
            text=True,
            timeout=10,
            check=False
        )
        
        if result.returncode == 0:
            return True, result.stdout
        else:
            error_msg = result.stderr.strip() or "Comando falló sin mensaje de error"
            return False, error_msg
            
    except subprocess.TimeoutExpired:
        return False, f"Timeout ejecutando comando"
    except Exception as e:
        return False, f"Error inesperado: {str(e)}"


def _load_config() -> Optional[dict]:
    if not os.path.exists(CONFIG_FILE):
        return None
    try:
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return None


def _update_status(status: int) -> None:
    cfg = _load_config() or {}
    cfg["status"] = status
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=4)


# -----------------------------
# Acciones públicas (Admin API)
# -----------------------------

def start(params: Dict[str, Any] = None) -> Tuple[bool, str]:
    create_module_config_directory("wan")
    create_module_log_directory("wan")
    cfg = _load_config()
    if not cfg:
        return False, "Configuración WAN no encontrada"

    iface = cfg.get("interface")
    mode = cfg.get("mode")
    if not iface or not mode:
        return False, "Configuración WAN incompleta"

    # Verificar que la interfaz existe
    success, _ = _run_command(["/usr/sbin/ip", "link", "show", iface])
    if not success:
        return False, f"La interfaz {iface} no existe"

    try:
        if mode == "dhcp":
            # Lanzar dhcpcd en background (retorna inmediatamente)
            success, msg = _run_command(["/usr/sbin/dhcpcd", iface])
            if not success:
                return False, f"Error al lanzar DHCP en {iface}: {msg}"
            
            _update_status(1)
            return True, f"DHCP iniciado en {iface} (configuración en proceso)"

        elif mode == "manual":
            _start_manual(iface, cfg)
        else:
            return False, f"Modo WAN desconocido: {mode}"

        _update_status(1)
        return True, f"WAN iniciada ({mode})"

    except Exception as e:
        return False, str(e)

def stop(params: Dict[str, Any] = None) -> Tuple[bool, str]:
    create_module_config_directory("wan")
    create_module_log_directory("wan")
    cfg = _load_config()
    iface = cfg.get("interface") if cfg else None
    if not iface:
        return False, "Interfaz WAN no definida"

    try:
        # Intentar revertir resoluciones DNS para la interfaz
        _run_command(["/usr/bin/resolvectl", "revert", iface])

        # Intentar bajar la interfaz
        success, msg = _run_command(["/usr/sbin/ip", "link", "set", iface, "down"])
        if not success:
            return False, f"Error al deshabilitar la interfaz {iface}"

        # Limpiar la dirección IP
        success, msg = _run_command(["/usr/sbin/ip", "a", "flush", "dev", iface])
        if not success:
            return False, f"Error al limpiar la dirección IP de la interfaz {iface}"

        # Limpiar las rutas asociadas a la interfaz
        success, msg = _run_command(["/usr/sbin/ip", "r", "flush", "dev", iface])
        if not success:
            return False, f"Error al limpiar las rutas de la interfaz {iface}"

        # Detener el servicio dhcpcd
        _run_command(["/usr/sbin/dhcpcd", "-k", iface])

        # Actualizar el estado
        _update_status(0)

        return True, "WAN detenida exitosamente"
    
    except Exception as e:
        return False, f"Error inesperado al detener WAN: {e}"


def restart(params: Dict[str, Any] = None) -> Tuple[bool, str]:
    ok, msg = stop()
    if not ok:
        return False, msg
    return start()

def status(params: Dict[str, Any] = None) -> Tuple[bool, str]:
    create_module_config_directory("wan")
    create_module_log_directory("wan")
    cfg = _load_config()
    iface = cfg.get("interface") if cfg else None
    if not iface:
        return False, "Interfaz WAN no definida"

    try:
        # Comprobar si la interfaz existe
        success, ip_info = _run_command(["/usr/sbin/ip", "a", "show", iface])
        if not success:
            return False, f"La interfaz {iface} no existe"

        # Obtener rutas, aunque la interfaz no tenga rutas configuradas no es crítico
        success, routes = _run_command(["/usr/sbin/ip", "r"])
        if not success:
            routes = "No se pudieron obtener las rutas"

        return True, f"{ip_info}\n\n{routes}"
    except Exception as e:
        return False, f"Error obteniendo status: {e}"

def config(params: Dict[str, Any]) -> Tuple[bool, str]:
    create_module_config_directory("wan")
    create_module_log_directory("wan")
    required = ["mode", "interface"]
    for r in required:
        if not params.get(r):
            return False, f"Falta el parámetro '{r}'"

    if params["mode"] == "manual":
        for r in ["ip", "mask", "gateway", "dns"]:
            if not params.get(r):
                return False, f"Falta el parámetro '{r}' para modo manual"

    try:
        # Cargar configuración existente para preservar el status
        existing_cfg = _load_config() or {}
        
        # Actualizar con los nuevos parámetros
        existing_cfg.update(params)
        
        # Guardar la configuración completa
        os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
        with open(CONFIG_FILE, "w") as f:
            json.dump(existing_cfg, f, indent=4)
        return True, "Configuración WAN guardada"
    except Exception as e:
        return False, f"Error guardando configuración WAN: {e}"


# -----------------------------
# Helpers internos
# -----------------------------

def _start_manual(iface: str, cfg: dict):
    _run_command(["/usr/sbin/ip", "a", "flush", "dev", iface])
    _run_command(["/usr/sbin/ip", "a", "add", f"{cfg['ip']}/{cfg['mask']}", "dev", iface])
    _run_command(["/usr/sbin/ip", "l", "set", iface, "up"])
    _run_command(["/usr/sbin/ip", "r", "add", "default", "via", cfg["gateway"], "dev", iface])

    dns = cfg.get("dns", [])
    if isinstance(dns, str):
        dns = [d.strip() for d in dns.split(",") if d.strip()]

    if dns:
        _run_command(["/usr/bin/resolvectl", "revert", iface])
        _run_command(["/usr/bin/resolvectl", "dns", iface] + dns)


# -----------------------------
# Whitelist de acciones
# -----------------------------

ALLOWED_ACTIONS = {
    "start": start,
    "stop": stop,
    "restart": restart,
    "status": status,
    "config": config,
}