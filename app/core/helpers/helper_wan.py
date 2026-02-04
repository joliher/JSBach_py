# app/core/helpers/helper_wan.py
"""Helper functions para el módulo WAN."""

import asyncio
import time
from typing import Tuple, Optional
from ...utils.helpers import run_command, load_json_config, save_json_config


def verify_wan_status(config_file: str) -> Tuple[bool, Optional[str]]:
    """
    Verifica que WAN está completamente funcional:
    - Interfaz existe y está UP
    - Tiene IP asignada
    - Tiene ruta por defecto
    
    Args:
        config_file: Ruta al archivo wan.json
    
    Retorna: (is_valid: bool, interface: Optional[str])
    """
    cfg = load_json_config(config_file)
    if not cfg:
        return False, None
    
    iface = cfg.get("interface")
    if not iface:
        return False, None
    
    # Verificar que la interfaz existe y está UP
    success, ip_info = run_command(["/usr/sbin/ip", "a", "show", iface], use_sudo=False)
    if not success:
        return False, None  # Interfaz no existe
    
    is_up = "state UP" in ip_info or ",UP," in ip_info
    if not is_up:
        return False, None  # Interfaz no está UP
    
    # Verificar que tiene IP asignada
    has_ip = "inet " in ip_info
    if not has_ip:
        return False, None  # Sin IP asignada
    
    # Verificar que tiene ruta por defecto
    success, routes = run_command(["/usr/sbin/ip", "r"], use_sudo=False)
    if not success or "default" not in routes:
        return False, None  # Sin ruta por defecto
    
    return True, iface


async def verify_dhcp_assignment(iface: str, config_file: str, max_wait: int = 30) -> None:
    """
    Verifica en background que se asignó una IP por DHCP.
    Si después de max_wait segundos no se asignó, detiene el proceso.
    Se ejecuta como tarea asyncio sin bloquear el flujo principal.
    
    También verifica que la interfaz está UP y tiene ruta por defecto.
    
    Args:
        iface: Nombre de la interfaz
        config_file: Ruta al archivo wan.json
        max_wait: Segundos máximos para esperar
    """
    start_time = time.time()
    check_interval = 2  # Verificar cada 2 segundos
    
    while (time.time() - start_time) < max_wait:
        await asyncio.sleep(check_interval)
        
        # Verificar si la interfaz tiene una IP asignada
        success, ip_info = run_command(["/usr/sbin/ip", "a", "show", iface], use_sudo=False)
        
        if not success:
            continue
        
        # Verificar que tiene IP, está UP y tiene ruta por defecto
        has_ip = "inet " in ip_info
        is_up = "state UP" in ip_info or ",UP," in ip_info
        
        if not (has_ip and is_up):
            continue
        
        # Verificar ruta por defecto
        success_routes, routes = run_command(["/usr/sbin/ip", "r"], use_sudo=False)
        if success_routes and "default" in routes:
            # Todo está bien, WAN está completamente funcional
            cfg = load_json_config(config_file) or {}
            cfg["status"] = 1
            cfg.pop("dhcp_error", None)
            save_json_config(config_file, cfg)
            return  # IP asignada correctamente con todas las validaciones, terminar
