# app/core/wan.py

import os
from typing import Dict, Any, Tuple
from ..utils.global_functions import create_module_config_directory, create_module_log_directory
from ..utils.validators import validate_ip_address, validate_interface_name
from ..utils.helpers import (
    load_json_config, save_json_config, update_module_status,
    run_command, validate_interface_name as validate_iface
)
from .helpers import verify_wan_status, verify_dhcp_assignment

# Config file in V4 structure
CONFIG_FILE = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "config", "wan", "wan.json")
)

# Alias helpers para compatibilidad
_load_config = lambda: load_json_config(CONFIG_FILE)
_run_command = lambda cmd: run_command(cmd)
_update_status = lambda status: update_module_status(CONFIG_FILE, status)

# Aliases para funciones de helpers (compatibilidad con el resto del código)
_verify_wan_status = lambda: verify_wan_status(CONFIG_FILE)
_verify_dhcp_assignment = lambda iface, max_wait=30: verify_dhcp_assignment(iface, CONFIG_FILE, max_wait)


# --------------------------------
# Acciones públicas (Admin API)
# --------------------------------

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
            
            # NO establecer status a 1 aún, esperar a que se cumplan todas las validaciones
            # Limpiar cualquier error previo de DHCP
            cfg = _load_config() or {}
            cfg.pop("dhcp_error", None)
            cfg["status"] = 0  # Estado pendiente hasta que se verifique
            save_json_config(CONFIG_FILE, cfg)
            
            # Crear una tarea asyncio que verifique en background si se cumplieron todas las validaciones
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
            
            return True, f"DHCP iniciado en {iface} (verificando IP, estado físico y ruta en background)"

        elif mode == "manual":
            _start_manual(iface, cfg)
            # Para modo manual, verificar que se cumplan las validaciones
            is_valid, _ = _verify_wan_status()
            if not is_valid:
                _update_status(0)
                return False, "Configuración manual incompleta: Sin IP, interfaz no está UP o sin ruta por defecto"
            _update_status(1)
        else:
            return False, f"Modo WAN desconocido: {mode}"

        return True, f"WAN iniciada ({mode})"

    except Exception as e:
        _update_status(0)
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
            save_json_config(CONFIG_FILE, cfg)
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

    # Validar que mode es un valor permitido
    mode = params["mode"]
    allowed_modes = ["manual", "dhcp"]
    if mode not in allowed_modes:
        return False, f"Modo inválido: '{mode}'. Valores permitidos: {', '.join(allowed_modes)}"

    if params["mode"] == "manual":
        for r in ["ip", "mask", "gateway", "dns"]:
            if not params.get(r):
                return False, f"Falta el parámetro '{r}' para modo manual"
        
        # Validar IP
        valid, error = validate_ip_address(params["ip"])
        if not valid:
            return False, f"IP inválida: {error}"
        
        # Validar Gateway
        valid, error = validate_ip_address(params["gateway"])
        if not valid:
            return False, f"Gateway inválido: {error}"
        
        # Validar DNS (puede ser lista o string separado por comas)
        dns = params.get("dns", [])
        if isinstance(dns, str):
            dns = [d.strip() for d in dns.split(",") if d.strip()]
        for dns_ip in dns:
            valid, error = validate_ip_address(dns_ip)
            if not valid:
                return False, f"DNS inválido '{dns_ip}': {error}"

    # Validar nombre de interfaz
    iface = params["interface"]
    valid, error = validate_interface_name(iface)
    if not valid:
        return False, f"Interfaz inválida: {error}"
    
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
        save_json_config(CONFIG_FILE, existing_cfg)
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