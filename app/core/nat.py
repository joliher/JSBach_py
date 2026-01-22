# app/core/nat.py

import subprocess
import json
import os
from typing import Dict, Any, Tuple, Optional
from ..utils.global_functions import create_module_config_directory, create_module_log_directory

# Config file in V4 structure
CONFIG_FILE = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "config", "nat", "nat.json")
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


def _save_config(config: dict) -> None:
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=4)


def _update_status(status: int) -> None:
    cfg = _load_config() or {"interface": "", "status": 0}
    cfg["status"] = status
    _save_config(cfg)


# -----------------------------
# Acciones públicas (Admin API)
# -----------------------------

def start(params: Dict[str, Any] = None) -> Tuple[bool, str]:
    create_module_config_directory("nat")
    create_module_log_directory("nat")
    config = _load_config()
    if not config:
        return False, "Configuración NAT no encontrada"

    interfaz = config.get("interface")
    if not interfaz:
        return False, "Interfaz NAT no definida"

    # Comprobar si NAT ya está activo
    cmd = ["/usr/sbin/iptables", "-t", "nat", "-C", "POSTROUTING", "-o", interfaz, "-j", "MASQUERADE"]
    success, _ = _run_command(cmd)
    if success:
        return True, f"NAT ya activado en {interfaz}"

    # Activar IP forwarding usando sysctl
    success, msg = _run_command(["/usr/sbin/sysctl", "-w", "net.ipv4.ip_forward=1"])
    if not success:
        return False, f"Error activando IP forwarding: {msg}"
    
    # Añadir regla NAT
    success, msg = _run_command(["/usr/sbin/iptables", "-t", "nat", "-A", "POSTROUTING", "-o", interfaz, "-j", "MASQUERADE"])
    if not success:
        return False, f"Error añadiendo regla NAT: {msg}"
    
    _update_status(1)
    return True, f"NAT activado en {interfaz}"


def stop(params: Dict[str, Any] = None) -> Tuple[bool, str]:
    create_module_config_directory("nat")
    create_module_log_directory("nat")
    config = _load_config()
    if not config:
        return False, "Configuración NAT no encontrada"

    interfaz = config.get("interface")
    if not interfaz:
        return False, "Interfaz NAT no definida"

    # Verificar si otros módulos dependen del IP forwarding
    base_config_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "config"))
    modules_to_check = {
        "firewall": os.path.join(base_config_dir, "firewall", "firewall.json"),
        "dmz": os.path.join(base_config_dir, "dmz", "dmz.json")
    }
    
    active_modules = []
    for module_name, config_path in modules_to_check.items():
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    module_config = json.load(f)
                    if module_config.get("status") == 1:
                        active_modules.append(module_name)
            except Exception:
                # Si hay error leyendo, asumimos que podría estar activo
                pass
    
    if active_modules:
        modules_str = ", ".join(active_modules)
        return False, f"No se puede desactivar IP forwarding: los módulos [{modules_str}] están activos y lo requieren. Detén primero esos módulos."

    # Desactivar IP forwarding usando sysctl
    success, msg = _run_command(["/usr/sbin/sysctl", "-w", "net.ipv4.ip_forward=0"])
    if not success:
        return False, f"Error desactivando IP forwarding: {msg}"
    
    # Eliminar regla NAT (no importa si falla, puede que no exista)
    _run_command(["/usr/sbin/iptables", "-t", "nat", "-D", "POSTROUTING", "-o", interfaz, "-j", "MASQUERADE"])
    
    _update_status(0)
    return True, f"NAT desactivado en {interfaz}"


def restart(params: Dict[str, Any] = None) -> Tuple[bool, str]:
    ok, msg = stop()
    if not ok:
        return False, msg
    return start()


def status(params: Dict[str, Any] = None) -> Tuple[bool, str]:
    create_module_config_directory("nat")
    create_module_log_directory("nat")
    config = _load_config()
    if not config:
        return False, "Configuración NAT no encontrada"

    interfaz = config.get("interface")
    if not interfaz:
        return False, "Interfaz NAT no definida"

    # Verificar IP forwarding
    success, output = _run_command(["/usr/sbin/sysctl", "-n", "net.ipv4.ip_forward"])
    if not success:
        return False, f"Error verificando NAT: {output}"
    
    ip_forward = output.strip()
    
    # Verificar regla NAT
    cmd = ["/usr/sbin/iptables", "-t", "nat", "-C", "POSTROUTING", "-o", interfaz, "-j", "MASQUERADE"]
    nat_active, _ = _run_command(cmd)
    
    if ip_forward == "1" and nat_active:
        return True, f"NAT ACTIVADO en {interfaz}"
    else:
        return True, f"NAT DESACTIVADO en {interfaz}"


def config(params: Dict[str, Any]) -> Tuple[bool, str]:
    create_module_config_directory("nat")
    create_module_log_directory("nat")
    
    # Validar parámetros
    if not params:
        return False, "No se proporcionaron parámetros"
    
    if not isinstance(params, dict):
        return False, "Los parámetros deben ser un diccionario"
    
    interfaz = params.get("interface")
    
    # Validar interface (requerido)
    if not interfaz:
        return False, "Falta parámetro obligatorio 'interface'"
    
    if not isinstance(interfaz, str):
        return False, "El parámetro 'interface' debe ser una cadena de texto"
    
    interfaz = interfaz.strip()
    if not interfaz:
        return False, "El parámetro 'interface' no puede estar vacío"
    
    # Validar formato de interfaz (eth0, ens3, enp0s3, wlan0, etc.)
    import re
    if not re.match(r'^[a-zA-Z0-9]+$', interfaz):
        return False, f"Formato de interfaz inválido: '{interfaz}'. Debe ser alfanumérico (ej: eth0, ens3, wlan0)"
    
    # Verificar que la interfaz existe en el sistema
    success, output = _run_command(["/usr/sbin/ip", "link", "show", interfaz])
    if not success:
        return False, f"La interfaz '{interfaz}' no existe en el sistema"

    # Cargar configuración existente para preservar el status
    existing_cfg = _load_config() or {}
    existing_cfg["interface"] = interfaz
    if "status" not in existing_cfg:
        existing_cfg["status"] = 0
    
    _save_config(existing_cfg)
    return True, f"Configuración NAT guardada: interfaz {interfaz}"


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