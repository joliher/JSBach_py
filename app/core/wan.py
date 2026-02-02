# app/core/wan.py

import subprocess
import json
import os
import fcntl
import asyncio
import time
import re
from typing import Dict, Any, Tuple, Optional
from ..utils.global_functions import create_module_config_directory, create_module_log_directory

# Config file in V4 structure
CONFIG_FILE = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "config", "wan", "wan.json")
)

# -----------------------------
# Utilidades internas
# -----------------------------

def _sanitize_interface_name(name: str) -> bool:
    """Valida que el nombre de interfaz sea seguro (solo alfanuméricos, puntos, guiones, guiones bajos)."""
    if not name or not isinstance(name, str):
        return False
    return bool(re.match(r'^[a-zA-Z0-9._-]+$', name))


def _run_command(cmd: list) -> Tuple[bool, str]:
    """Ejecutar comando con sudo automáticamente."""
    try:
        full_cmd = ["sudo"] + cmd
        result = subprocess.run(
            full_cmd,
            capture_output=True,
            text=True,
            timeout=30,
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


async def _verify_dhcp_assignment(iface: str, max_wait: int = 30) -> None:
    """
    Verifica en background que se asignó una IP por DHCP.
    Si después de max_wait segundos no se asignó, detiene el proceso.
    Se ejecuta como tarea asyncio sin bloquear el flujo principal.
    """
    start_time = time.time()
    check_interval = 2  # Verificar cada 2 segundos
    
    while (time.time() - start_time) < max_wait:
        await asyncio.sleep(check_interval)
        
        # Verificar si la interfaz tiene una IP asignada
        success, ip_info = _run_command(["/usr/sbin/ip", "a", "show", iface])
        
        if success and "inet " in ip_info:  # "inet " indica IPv4
            # Extractar la IP asignada para logging
            lines = ip_info.split('\n')
            for line in lines:
                if "inet " in line:
                    ip_line = line.strip()
                    # Logging de éxito (opcional: escribir en log)
                    break
            return  # IP asignada correctamente, terminar verificación
    
    # Si llegamos aquí, DHCP no asignó IP en el tiempo límite
    # Registrar error y detener DHCP
    _run_command(["/usr/sbin/dhcpcd", "-k", iface])
    cfg = _load_config() or {}
    cfg["status"] = 0
    cfg["dhcp_error"] = "DHCP timeout: IP no fue asignada en 30 segundos"
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    with open(CONFIG_FILE, "w") as f:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        json.dump(cfg, f, indent=4)
        fcntl.flock(f.fileno(), fcntl.LOCK_UN)


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
            success, msg = _run_command(["/usr/sbin/dhcpcd", "-b", iface])
            if not success:
                return False, f"Error al lanzar DHCP en {iface}: {msg}"
            
            # Limpiar cualquier error previo de DHCP
            cfg = _load_config() or {}
            cfg.pop("dhcp_error", None)
            
            _update_status(1)
            
            # Crear una tarea asyncio que verifique en background si se asignó la IP
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    # Si ya hay un loop corriendo (ej: en contexto de FastAPI)
                    asyncio.create_task(_verify_dhcp_assignment(iface))
                else:
                    # Sino, crear la tarea en el loop actual
                    loop.create_task(_verify_dhcp_assignment(iface))
            except RuntimeError:
                # Si no hay loop, intentar crear uno nuevo
                try:
                    asyncio.create_task(_verify_dhcp_assignment(iface))
                except:
                    pass  # Si falla, al menos DHCP se inició correctamente
            
            return True, f"DHCP iniciado en {iface} (verificando asignación de IP en background)"

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
        # Verificar si hay error pendiente de DHCP
        if cfg and cfg.get("dhcp_error"):
            dhcp_error = cfg.get("dhcp_error")
            # Limpiar el error después de reportarlo
            cfg.pop("dhcp_error", None)
            os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
            with open(CONFIG_FILE, "w") as f:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                json.dump(cfg, f, indent=4)
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
            return False, f"Error de DHCP: {dhcp_error}"
        
        # Comprobar si la interfaz existe y su estado
        success, ip_info = _run_command(["/usr/sbin/ip", "a", "show", iface])
        if not success:
            return False, f"La interfaz {iface} no existe"

        # Verificar si la interfaz está UP o DOWN
        is_up = "state UP" in ip_info or ",UP," in ip_info
        interface_status = "🟢 UP (activa)" if is_up else "🔴 DOWN (inactiva)"
        
        # Verificar si tiene IP asignada
        has_ip = "inet " in ip_info
        ip_status = "✅ Tiene IP asignada" if has_ip else "⚠️ Sin IP asignada"
        
        # Obtener rutas
        success, routes = _run_command(["/usr/sbin/ip", "r"])
        if not success:
            routes = "No se pudieron obtener las rutas"
        
        # Verificar si hay ruta por defecto
        has_default_route = "default" in routes
        route_status = "✅ Tiene ruta por defecto" if has_default_route else "⚠️ Sin ruta por defecto"

        status_summary = f"""Estado de WAN:
==================
Interfaz: {iface}
Estado físico: {interface_status}
Estado IP: {ip_status}
Estado rutas: {route_status}

Detalles de la interfaz:
{ip_info}

Tabla de rutas:
{routes}"""

        return True, status_summary
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

    # Validar nombre de interfaz seguro
    iface = params["interface"]
    if not _sanitize_interface_name(iface):
        return False, f"Nombre de interfaz inválido: '{iface}'. Solo use caracteres alfanuméricos, puntos, guiones y guiones bajos."
    
    # Validar que la interfaz existe en el sistema
    success, _ = _run_command(["/usr/sbin/ip", "link", "show", iface])
    if not success:
        return False, f"La interfaz '{iface}' no existe en el sistema. Verifique con 'ip link show'."

    try:
        # Cargar configuración existente para preservar el status
        existing_cfg = _load_config() or {}
        
        # Actualizar con los nuevos parámetros
        existing_cfg.update(params)
        
        # Guardar la configuración completa
        os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
        with open(CONFIG_FILE, "w") as f:
            # Lock exclusivo para prevenir race conditions
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            json.dump(existing_cfg, f, indent=4)
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
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