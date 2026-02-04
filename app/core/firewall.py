# app/core/firewall.py
# Módulo de Firewall - Arquitectura jerárquica con cadenas por VLAN
# VERSION 2.0 - Refactorización completa

import os
import re
import json
import logging
from typing import Dict, Any, Tuple, List
from ..utils.global_functions import (
    create_module_config_directory,
    create_module_log_directory,
    log_action
)
from ..utils.validators import validate_vlan_id, validate_ip_address
from ..utils.helpers import run_command
from .helpers import (
    firewall_ensure_dirs, load_firewall_config, load_vlans_config, load_wan_config, save_firewall_config,
    firewall_check_wan_configured, ensure_input_protection_chain, ensure_forward_protection_chain,
    setup_wan_protection, create_input_vlan_chain, create_forward_vlan_chain,
    remove_input_vlan_chain, remove_forward_vlan_chain, apply_whitelist, apply_single_whitelist_rule
)

# Configurar logging
logger = logging.getLogger(__name__)

# Rutas de configuración
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
FIREWALL_CONFIG_FILE = os.path.join(BASE_DIR, "config", "firewall", "firewall.json")
VLANS_CONFIG_FILE = os.path.join(BASE_DIR, "config", "vlans", "vlans.json")
WAN_CONFIG_FILE = os.path.join(BASE_DIR, "config", "wan", "wan.json")

# Alias helpers para compatibilidad
_ensure_dirs = firewall_ensure_dirs
_load_firewall_config = load_firewall_config
_load_vlans_config = load_vlans_config
_load_wan_config = load_wan_config
_save_firewall_config = save_firewall_config
_run_command = lambda cmd: run_command(cmd)
_check_wan_configured = firewall_check_wan_configured
_ensure_input_protection_chain = ensure_input_protection_chain
_ensure_forward_protection_chain = ensure_forward_protection_chain
_setup_wan_protection = setup_wan_protection
_create_input_vlan_chain = create_input_vlan_chain
_create_forward_vlan_chain = create_forward_vlan_chain
_remove_input_vlan_chain = remove_input_vlan_chain
_remove_forward_vlan_chain = remove_forward_vlan_chain
_apply_whitelist = apply_whitelist
_apply_single_whitelist_rule = apply_single_whitelist_rule


# =============================================================================
# FUNCIONES PRINCIPALES
# =============================================================================

def start(params: Dict[str, Any] = None) -> Tuple[bool, str]:
    """Iniciar firewall con nueva arquitectura jerárquica."""
    logger.info("=== INICIO: firewall start ===")
    _ensure_dirs()
    
    # Verificar WAN configurada
    if not _check_wan_configured():
        msg = "Error: la WAN debe estar configurada antes de iniciar el firewall"
        logger.error(msg)
        log_action("firewall", f"start - ERROR: {msg}", "ERROR")
        return False, msg
    
    # Cargar VLANs desde vlans.json
    vlans_cfg = _load_vlans_config()
    vlans = vlans_cfg.get("vlans", [])
    
    if not vlans:
        msg = "No hay VLANs configuradas. Configure VLANs primero."
        logger.warning(msg)
        return False, msg
    
    # Crear cadenas protegidas (posiciones fijas)
    _ensure_input_protection_chain()
    _ensure_forward_protection_chain()
    _setup_wan_protection()
    
    # Cargar configuración del firewall
    fw_cfg = _load_firewall_config()
    if "vlans" not in fw_cfg:
        fw_cfg["vlans"] = {}
    
    # Sincronizar: eliminar VLANs obsoletas de firewall.json
    active_vlan_ids = {str(vlan.get("id")) for vlan in vlans if vlan.get("id") is not None}
    vlans_to_remove = [vid for vid in fw_cfg["vlans"].keys() if vid not in active_vlan_ids]
    
    for vlan_id in vlans_to_remove:
        logger.info(f"Eliminando VLAN {vlan_id} obsoleta de firewall.json")
        vlan_ip = fw_cfg["vlans"][vlan_id].get("ip", "")
        if vlan_ip:
            _remove_input_vlan_chain(int(vlan_id), vlan_ip)
            _remove_forward_vlan_chain(int(vlan_id), vlan_ip)
        del fw_cfg["vlans"][vlan_id]
    
    results = []
    errors = []
    
    # Procesar cada VLAN
    for vlan in vlans:
        vlan_id = vlan.get("id")
        vlan_name = vlan.get("name", "")
        vlan_ip_network = vlan.get("ip_network", "")
        
        logger.info(f"Procesando VLAN {vlan_id} ({vlan_name})")
        
        if not vlan_ip_network:
            errors.append(f"VLAN {vlan_id}: Sin IP de red configurada")
            continue
        
        # Crear cadenas INPUT_VLAN_X y FORWARD_VLAN_X
        if not _create_input_vlan_chain(vlan_id, vlan_ip_network):
            errors.append(f"VLAN {vlan_id}: Error creando cadena INPUT")
            continue
        
        if not _create_forward_vlan_chain(vlan_id, vlan_ip_network):
            errors.append(f"VLAN {vlan_id}: Error creando cadena FORWARD")
            continue
        
        # Inicializar configuración en firewall.json
        if str(vlan_id) not in fw_cfg["vlans"]:
            fw_cfg["vlans"][str(vlan_id)] = {
                "name": vlan_name,
                "enabled": True,
                "whitelist_enabled": False,
                "whitelist": [],
                "ip": vlan_ip_network,
                "isolated": False,
                "restricted": False
            }
        else:
            # Actualizar campos básicos
            fw_cfg["vlans"][str(vlan_id)]["name"] = vlan_name
            fw_cfg["vlans"][str(vlan_id)]["enabled"] = True
            fw_cfg["vlans"][str(vlan_id)]["ip"] = vlan_ip_network
        
        # Aplicar whitelist si está habilitada
        vlan_cfg = fw_cfg["vlans"][str(vlan_id)]
        if vlan_cfg.get("whitelist_enabled", False):
            whitelist = vlan_cfg.get("whitelist", [])
            success, msg = _apply_whitelist(vlan_id, whitelist)
            if not success:
                errors.append(f"VLAN {vlan_id}: Error aplicando whitelist")
        
        results.append(f"VLAN {vlan_id} ({vlan_name}): Configurada")
    
    # Guardar configuración
    fw_cfg["status"] = 1
    _save_firewall_config(fw_cfg)
    
    # POLÍTICAS PREDETERMINADAS
    # VLAN 1: Aislar automáticamente
    if "1" in fw_cfg["vlans"]:
        logger.info("Aplicando política: VLAN 1 aislada por defecto")
        success, msg = aislar({"vlan_id": 1, "from_start": True})
        if success:
            results.append("VLAN 1: Aislada (política predeterminada)")
        else:
            errors.append(f"VLAN 1: Error aislando - {msg}")
    
    # Resto de VLANs: Restringir automáticamente
    logger.info("Aplicando restricciones predeterminadas a VLANs")
    applied_restrictions = []
    for vlan_id in active_vlan_ids:
        if vlan_id == "1":
            continue
        success, msg = restrict({"vlan_id": int(vlan_id), "suppress_log": True})
        if success:
            applied_restrictions.append(vlan_id)
            results.append(f"VLAN {vlan_id}: Restringida (política predeterminada)")
        else:
            errors.append(f"VLAN {vlan_id}: Error restringiendo - {msg}")
    
    # Sincronizar restricted=true en JSON
    fw_cfg_final = _load_firewall_config()
    for vlan_id in applied_restrictions:
        if vlan_id in fw_cfg_final["vlans"]:
            fw_cfg_final["vlans"][vlan_id]["restricted"] = True
    _save_firewall_config(fw_cfg_final)
    
    msg = "Firewall iniciado:\n" + "\n".join(results)
    if errors:
        msg += "\n\nErrores:\n" + "\n".join(errors)
        logger.warning("Firewall iniciado con errores")
    else:
        logger.info("Firewall iniciado correctamente")
    
    log_action("firewall", f"start - {'SUCCESS' if not errors else 'PARTIAL'}", "WARNING" if errors else "INFO")
    logger.info("=== FIN: firewall start ===")
    
    return len(errors) == 0, msg


def stop(params: Dict[str, Any] = None) -> Tuple[bool, str]:
    """Detener firewall - eliminar todas las cadenas de VLANs."""
    logger.info("=== INICIO: firewall stop ===")
    _ensure_dirs()
    
    fw_cfg = _load_firewall_config()
    vlans = fw_cfg.get("vlans", {})
    
    if not vlans:
        msg = "No hay VLANs configuradas en el firewall"
        logger.warning(msg)
        return True, msg
    
    results = []
    
    # Eliminar cadenas de cada VLAN
    for vlan_id, vlan_data in vlans.items():
        vlan_ip = vlan_data.get("ip", "")
        
        if not vlan_ip:
            continue
        
        # Desrestringir todas las VLANs
        unrestrict({"vlan_id": int(vlan_id), "suppress_log": True})
        
        # Desaislar todas excepto VLAN 1
        if vlan_id != "1" and vlan_data.get("isolated", False):
            desaislar({"vlan_id": int(vlan_id), "suppress_log": True})
        
        # Eliminar cadenas
        _remove_input_vlan_chain(int(vlan_id), vlan_ip)
        _remove_forward_vlan_chain(int(vlan_id), vlan_ip)
        
        # Actualizar configuración
        vlan_data["enabled"] = False
        vlan_data["restricted"] = False
        if vlan_id != "1":
            vlan_data["isolated"] = False
        
        results.append(f"VLAN {vlan_id}: Desactivada")
    
    # FIX BUG #7: Eliminar vínculos y cadenas protegidas
    # Limpiar contenido
    _run_command(["/usr/sbin/iptables", "-F", "INPUT_PROTECTION"])
    _run_command(["/usr/sbin/iptables", "-F", "FORWARD_PROTECTION"])
    
    # Desvincular desde INPUT y FORWARD
    _run_command(["/usr/sbin/iptables", "-D", "INPUT", "-j", "INPUT_PROTECTION"])
    _run_command(["/usr/sbin/iptables", "-D", "FORWARD", "-j", "FORWARD_PROTECTION"])
    
    # Eliminar cadenas
    _run_command(["/usr/sbin/iptables", "-X", "INPUT_PROTECTION"])
    _run_command(["/usr/sbin/iptables", "-X", "FORWARD_PROTECTION"])
    
    logger.info("Cadenas INPUT_PROTECTION y FORWARD_PROTECTION eliminadas")
    
    # Actualizar estado
    fw_cfg["status"] = 0
    _save_firewall_config(fw_cfg)
    
    msg = "Firewall detenido:\n" + "\n".join(results)
    logger.info("Firewall detenido correctamente")
    log_action("firewall", f"stop - SUCCESS: {msg}", "INFO")
    logger.info("=== FIN: firewall stop ===")
    
    return True, msg


def restart(params: Dict[str, Any] = None) -> Tuple[bool, str]:
    """Reiniciar firewall."""
    logger.info("=== INICIO: firewall restart ===")
    
    stop_success, stop_msg = stop(params)
    start_success, start_msg = start(params)
    
    msg = f"STOP:\n{stop_msg}\n\nSTART:\n{start_msg}"
    logger.info("=== FIN: firewall restart ===")
    
    return start_success, msg


def status(params: Dict[str, Any] = None) -> Tuple[bool, str]:
    """Obtener estado del firewall."""
    logger.info("=== INICIO: firewall status ===")
    
    fw_cfg = _load_firewall_config()
    vlans = fw_cfg.get("vlans", {})
    
    if not vlans:
        msg = "Firewall: Sin VLANs configuradas"
        logger.info(msg)
        return True, msg
    
    lines = ["Estado del Firewall:", "=" * 50]
    
    for vlan_id, vlan_data in vlans.items():
        vlan_name = vlan_data.get("name", "")
        enabled = vlan_data.get("enabled", False)
        isolated = vlan_data.get("isolated", False)
        restricted = vlan_data.get("restricted", False)
        whitelist_enabled = vlan_data.get("whitelist_enabled", False)
        
        status_str = "ACTIVA" if enabled else "INACTIVA"
        lines.append(f"\nVLAN {vlan_id} ({vlan_name}): {status_str}")
        lines.append(f"  Aislada: {'SÍ' if isolated else 'NO'}")
        lines.append(f"  Restringida: {'SÍ' if restricted else 'NO'}")
        lines.append(f"  Whitelist: {'ACTIVA' if whitelist_enabled else 'INACTIVA'}")
    
    msg = "\n".join(lines)
    logger.info("=== FIN: firewall status ===")
    return True, msg


# =============================================================================
# AISLAMIENTO (FORWARD_PROTECTION)
# =============================================================================

def aislar(params: Dict[str, Any] = None) -> Tuple[bool, str]:
    """Aislar una VLAN (añadir regla en FORWARD_PROTECTION)."""
    logger.info("=== INICIO: aislar ===")
    
    if not params or "vlan_id" not in params:
        return False, "Error: vlan_id requerido"
    
    vlan_id = params["vlan_id"]
    from_start = params.get("from_start", False)
    
    # PROTECCIÓN: VLAN 1 no puede ser aislada manualmente
    if vlan_id == 1 and not from_start:
        logger.warning("Intento de aislar VLAN 1 manualmente bloqueado")
        return False, "VLAN 1 no puede ser aislada manualmente. Solo se aísla automáticamente al iniciar el firewall."
    
    if vlan_id < 1 or vlan_id > 4094:
        return False, f"Error: vlan_id inválido: {vlan_id}"
    
    fw_cfg = _load_firewall_config()
    
    if str(vlan_id) not in fw_cfg.get("vlans", {}):
        return False, f"Error: VLAN {vlan_id} no está configurada"
    
    vlan_cfg = fw_cfg["vlans"][str(vlan_id)]
    vlan_ip_network = vlan_cfg.get("ip", "")
    
    if not vlan_ip_network:
        return False, f"Error: VLAN {vlan_id} no tiene IP configurada"
    
    ip_mask = vlan_ip_network if '/' in vlan_ip_network else f"{vlan_ip_network}/24"
    
    # Asegurar que existe FORWARD_PROTECTION
    _ensure_forward_protection_chain()
    
    # VLAN 1: bloquea tráfico HACIA ella (-d)
    if vlan_id == 1:
        logger.info(f"Aislando VLAN 1 con IP {ip_mask} (bloqueando tráfico entrante -d)")
        
        # Verificar si ya está aislada (regla puede estar en cualquier posición)
        success, _ = _run_command([
            "/usr/sbin/iptables", "-C", "FORWARD_PROTECTION", "-d", ip_mask, "-m", "conntrack", 
            "--ctstate", "NEW", "-j", "DROP"
        ])
        
        if success:
            logger.info("VLAN 1 ya está aislada (regla existe)")
            return True, "VLAN 1 ya estaba aislada"
        
        # Añadir regla en posición 1 (prioridad máxima)
        success, output = _run_command([
            "/usr/sbin/iptables", "-I", "FORWARD_PROTECTION", "1", "-d", ip_mask, "-m", "conntrack", 
            "--ctstate", "NEW", "-j", "DROP"
        ])
        
        if not success:
            logger.error(f"Error aislando VLAN 1: {output}")
            return False, f"Error al aislar VLAN 1: {output}"
        
        logger.info("VLAN 1 aislada con regla DROP insertada en posición 1")
        msg = "VLAN 1 aislada correctamente. Tráfico entrante bloqueado (saliente permitido)."
    
    else:
        # Otras VLANs: bloquea tráfico DESDE ella (-s)
        logger.info(f"Aislando VLAN {vlan_id} con IP {ip_mask} (bloqueando tráfico saliente -s)")
        
        # Verificar si ya está aislada
        success, _ = _run_command([
            "/usr/sbin/iptables", "-C", "FORWARD_PROTECTION", "-s", ip_mask, "-m", "conntrack", 
            "--ctstate", "NEW", "-j", "DROP"
        ])
        
        if success:
            logger.info(f"VLAN {vlan_id} ya está aislada")
            return True, f"VLAN {vlan_id} ya estaba aislada"
        
        # Añadir regla
        success, output = _run_command([
            "/usr/sbin/iptables", "-I", "FORWARD_PROTECTION", "1", "-s", ip_mask, "-m", "conntrack", 
            "--ctstate", "NEW", "-j", "DROP"
        ])
        
        if not success:
            logger.error(f"Error aislando VLAN {vlan_id}: {output}")
            return False, f"Error al aislar VLAN {vlan_id}: {output}"
        
        msg = f"VLAN {vlan_id} aislada correctamente. Las conexiones nuevas están bloqueadas."
    
    # Actualizar configuración
    vlan_cfg["isolated"] = True
    _save_firewall_config(fw_cfg)
    
    logger.info(f"VLAN {vlan_id} aislada exitosamente")
    logger.info("=== FIN: aislar ===")
    
    if not params.get("suppress_log", False):
        log_action("firewall", msg)
    
    return True, msg


def desaislar(params: Dict[str, Any] = None) -> Tuple[bool, str]:
    """Desaislar una VLAN (eliminar regla de FORWARD_PROTECTION)."""
    logger.info("=== INICIO: desaislar ===")
    
    if not params or "vlan_id" not in params:
        return False, "Error: vlan_id requerido"
    
    vlan_id = params["vlan_id"]
    
    # PROTECCIÓN: VLAN 1 no puede ser desaislada
    if vlan_id == 1:
        logger.warning("Intento de desaislar VLAN 1 bloqueado")
        return False, "VLAN 1 no puede ser desaislada. Permanece aislada mientras el firewall esté activo."
    
    if vlan_id < 1 or vlan_id > 4094:
        return False, f"Error: vlan_id inválido: {vlan_id}"
    
    fw_cfg = _load_firewall_config()
    
    if str(vlan_id) not in fw_cfg.get("vlans", {}):
        return False, f"Error: VLAN {vlan_id} no está configurada"
    
    vlan_cfg = fw_cfg["vlans"][str(vlan_id)]
    vlan_ip_network = vlan_cfg.get("ip", "")
    
    if not vlan_ip_network:
        return False, f"Error: VLAN {vlan_id} no tiene IP configurada"
    
    ip_mask = vlan_ip_network if '/' in vlan_ip_network else f"{vlan_ip_network}/24"
    
    logger.info(f"Desaislando VLAN {vlan_id} con IP {ip_mask}")
    
    # Verificar si está aislada
    success, _ = _run_command([
        "/usr/sbin/iptables", "-C", "FORWARD_PROTECTION", "-s", ip_mask, "-m", "conntrack", 
        "--ctstate", "NEW", "-j", "DROP"
    ])
    
    if not success:
        logger.info(f"VLAN {vlan_id} no estaba aislada")
        vlan_cfg["isolated"] = False
        _save_firewall_config(fw_cfg)
        return True, f"VLAN {vlan_id} no estaba aislada"
    
    # Eliminar regla
    success, output = _run_command([
        "/usr/sbin/iptables", "-D", "FORWARD_PROTECTION", "-s", ip_mask, "-m", "conntrack", 
        "--ctstate", "NEW", "-j", "DROP"
    ])
    
    if not success:
        logger.error(f"Error desaislando VLAN {vlan_id}: {output}")
        return False, f"Error al desaislar VLAN {vlan_id}: {output}"
    
    # Actualizar configuración
    vlan_cfg["isolated"] = False
    _save_firewall_config(fw_cfg)
    
    msg = f"VLAN {vlan_id} desaislada correctamente. El tráfico ha sido restaurado."
    logger.info(f"VLAN {vlan_id} desaislada exitosamente")
    logger.info("=== FIN: desaislar ===")
    
    if not params.get("suppress_log", False):
        log_action("firewall", msg)
    
    return True, msg


# =============================================================================
# RESTRICCIONES (INPUT_VLAN_X)
# =============================================================================

def restrict(params: Dict[str, Any] = None) -> Tuple[bool, str]:
    """Restringir acceso al router desde una VLAN (INPUT_VLAN_X).
    
    VLANs 1-2: DROP total
    Otras VLANs: Permitir DHCP, DNS, ICMP; DROP resto
    """
    logger.info("=== INICIO: restrict ===")
    
    if not params or "vlan_id" not in params:
        return False, "Error: vlan_id requerido"
    
    suppress_log = bool(params.get("suppress_log", False))
    
    try:
        vlan_id = int(params["vlan_id"])
    except (ValueError, TypeError):
        return False, f"Error: vlan_id debe ser entero"
    
    if vlan_id < 1 or vlan_id > 4094:
        return False, f"Error: vlan_id inválido"
    
    fw_cfg = _load_firewall_config()
    
    if str(vlan_id) not in fw_cfg.get("vlans", {}):
        return False, f"Error: VLAN {vlan_id} no está configurada"
    
    vlan_cfg = fw_cfg["vlans"][str(vlan_id)]
    vlan_ip_network = vlan_cfg.get("ip", "")
    
    if not vlan_ip_network:
        return False, f"Error: VLAN {vlan_id} no tiene IP configurada"
    
    ip_mask = vlan_ip_network if '/' in vlan_ip_network else f"{vlan_ip_network}/24"
    
    logger.info(f"Aplicando restricciones a VLAN {vlan_id} ({ip_mask})")
    
    # Verificar si ya está restringida
    if vlan_cfg.get("restricted", False):
        return True, f"VLAN {vlan_id} ya estaba restringida"
    
    chain_name = f"INPUT_VLAN_{vlan_id}"
    
    # Limpiar cadena
    _run_command(["/usr/sbin/iptables", "-F", chain_name])
    
    # Aplicar política según VLAN
    if vlan_id in [1, 2]:
        # DROP total
        logger.info(f"VLAN {vlan_id}: aplicando DROP total")
        _run_command(["/usr/sbin/iptables", "-A", chain_name, "-j", "DROP"])
        msg = f"VLAN {vlan_id} restringida: bloqueado acceso total al router"
    else:
        # Permitir DHCP, DNS, ICMP
        logger.info(f"VLAN {vlan_id}: permitiendo DHCP, DNS e ICMP; bloqueando resto")
        # DHCP (puertos 67 y 68 UDP)
        _run_command(["/usr/sbin/iptables", "-A", chain_name, "-p", "udp", "--dport", "67", "-j", "ACCEPT"])
        _run_command(["/usr/sbin/iptables", "-A", chain_name, "-p", "udp", "--dport", "68", "-j", "ACCEPT"])
        # DNS (puerto 53 UDP y TCP)
        _run_command(["/usr/sbin/iptables", "-A", chain_name, "-p", "udp", "--dport", "53", "-j", "ACCEPT"])
        _run_command(["/usr/sbin/iptables", "-A", chain_name, "-p", "tcp", "--dport", "53", "-j", "ACCEPT"])
        # ICMP
        _run_command(["/usr/sbin/iptables", "-A", chain_name, "-p", "icmp", "-j", "ACCEPT"])
        # DROP resto
        _run_command(["/usr/sbin/iptables", "-A", chain_name, "-j", "DROP"])
        msg = f"VLAN {vlan_id} restringida: solo DHCP, DNS e ICMP permitidos al router"
    
    # Marcar como restringida
    vlan_cfg["restricted"] = True
    _save_firewall_config(fw_cfg)
    
    logger.info(f"=== FIN: restrict - VLAN {vlan_id} restringida ===")
    if not suppress_log:
        log_action("firewall", msg)
    
    return True, msg


def unrestrict(params: Dict[str, Any] = None) -> Tuple[bool, str]:
    """Eliminar restricciones de una VLAN (INPUT_VLAN_X)."""
    logger.info("=== INICIO: unrestrict ===")
    
    if not params or "vlan_id" not in params:
        return False, "Error: vlan_id requerido"
    
    suppress_log = bool(params.get("suppress_log", False))
    
    try:
        vlan_id = int(params["vlan_id"])
    except (ValueError, TypeError):
        return False, f"Error: vlan_id debe ser entero"
    
    if vlan_id < 1 or vlan_id > 4094:
        return False, f"Error: vlan_id inválido"
    
    fw_cfg = _load_firewall_config()
    
    if str(vlan_id) not in fw_cfg.get("vlans", {}):
        return False, f"Error: VLAN {vlan_id} no está configurada"
    
    vlan_cfg = fw_cfg["vlans"][str(vlan_id)]
    
    logger.info(f"Eliminando restricciones de VLAN {vlan_id}")
    
    # Verificar si estaba restringida
    if not vlan_cfg.get("restricted", False):
        logger.info(f"VLAN {vlan_id} no estaba restringida")
        return True, f"VLAN {vlan_id} no estaba restringida"
    
    chain_name = f"INPUT_VLAN_{vlan_id}"
    
    # Limpiar cadena y permitir todo
    _run_command(["/usr/sbin/iptables", "-F", chain_name])
    _run_command(["/usr/sbin/iptables", "-A", chain_name, "-j", "ACCEPT"])
    
    # Marcar como no restringida
    vlan_cfg["restricted"] = False
    _save_firewall_config(fw_cfg)
    
    msg = f"VLAN {vlan_id} desrestringida correctamente"
    logger.info(f"=== FIN: unrestrict - VLAN {vlan_id} desrestringida ===")
    if not suppress_log:
        log_action("firewall", msg)
    
    return True, msg


# =============================================================================
# WHITELIST
# =============================================================================

def enable_whitelist(params: Dict[str, Any] = None) -> Tuple[bool, str]:
    """Habilitar whitelist en una VLAN específica."""
    logger.info("=== INICIO: enable_whitelist ===")
    
    if not params or "vlan_id" not in params:
        return False, "Error: vlan_id requerido"
    
    # Validar VLAN ID
    valid, error = validate_vlan_id(params["vlan_id"])
    if not valid:
        return False, f"VLAN inválida: {error}"
    
    vlan_id = int(params["vlan_id"])
    
    # VLANs 1 y 2 no permiten whitelist
    if vlan_id in (1, 2):
        return False, f"Error: VLAN {vlan_id} no permite configuración de whitelist"
    
    # Aceptar tanto 'ips' como 'whitelist' por compatibilidad
    whitelist = params.get("ips", params.get("whitelist", []))
    
    if isinstance(whitelist, str):
        whitelist = [whitelist] if whitelist else []
    elif not isinstance(whitelist, list):
        return False, f"Error: whitelist debe ser una lista"
    
    # Validar cada IP en la whitelist
    for ip in whitelist:
        valid, error = validate_ip_address(ip)
        if not valid:
            return False, f"IP inválida '{ip}': {error}"
    
    fw_cfg = _load_firewall_config()
    
    if str(vlan_id) not in fw_cfg.get("vlans", {}):
        return False, f"VLAN {vlan_id} no encontrada en firewall. Ejecute START primero."
    
    # Guardar configuración
    fw_cfg["vlans"][str(vlan_id)]["whitelist"] = whitelist
    fw_cfg["vlans"][str(vlan_id)]["whitelist_enabled"] = True
    _save_firewall_config(fw_cfg)
    
    # Aplicar whitelist
    success, msg = _apply_whitelist(vlan_id, whitelist)
    
    result_msg = f"Whitelist habilitada en VLAN {vlan_id}\n{msg}"
    logger.info(f"=== FIN: enable_whitelist - Success: {success} ===")
    
    if success:
        log_action("firewall", result_msg)
    
    return success, result_msg


def disable_whitelist(params: Dict[str, Any] = None) -> Tuple[bool, str]:
    """Deshabilitar whitelist en una VLAN específica."""
    logger.info("=== INICIO: disable_whitelist ===")
    
    if not params or "vlan_id" not in params:
        return False, "Error: vlan_id requerido"
    
    try:
        vlan_id = int(params["vlan_id"])
    except (ValueError, TypeError):
        return False, f"Error: vlan_id debe ser entero"
    
    fw_cfg = _load_firewall_config()
    
    if str(vlan_id) not in fw_cfg.get("vlans", {}):
        return False, f"VLAN {vlan_id} no encontrada"
    
    # Actualizar configuración
    fw_cfg["vlans"][str(vlan_id)]["whitelist_enabled"] = False
    _save_firewall_config(fw_cfg)
    
    # FIX BUG #5: Preservar reglas DMZ ACCEPT antes de limpiar
    # Cargar dmz.json para identificar IPs DMZ reales
    dmz_ips = set()
    try:
        dmz_cfg_path = os.path.join(BASE_DIR, "config", "dmz", "dmz.json")
        if os.path.exists(dmz_cfg_path):
            with open(dmz_cfg_path, "r") as f:
                dmz_cfg = json.load(f)
                for dest in dmz_cfg.get("destinations", []):
                    dmz_ips.add(dest.get("ip"))
    except Exception as e:
        logger.warning(f"No se pudo cargar dmz.json: {e}")
    
    # Buscar reglas ACCEPT con IPs DMZ reales en FORWARD_VLAN_X
    chain_name = f"FORWARD_VLAN_{vlan_id}"
    dmz_rules = []
    success, output = _run_command(["/usr/sbin/iptables", "-L", chain_name, "-n", "--line-numbers"])
    if success:
        for line in output.split('\n'):
            # Buscar reglas ACCEPT con destino específico usando regex
            if 'ACCEPT' in line:
                # Usar regex para extraer IP destino (más robusto que posiciones)
                # Patrón: buscar IP con CIDR (no 0.0.0.0/0)
                match = re.search(r'\s+([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(?:/\d+)?)\s+', line)
                if match:
                    dest_ip = match.group(1)
                    # Solo preservar si no es 0.0.0.0/0 y está en dmz_ips
                    if dest_ip != '0.0.0.0/0' and dest_ip in dmz_ips:
                        dmz_rules.append(dest_ip)
                        logger.info(f"Preservando regla DMZ ACCEPT para {dest_ip}")
    
    # Restaurar ACCEPT por defecto en FORWARD_VLAN_X
    _run_command(["/usr/sbin/iptables", "-F", chain_name])
    
    # Re-añadir reglas DMZ ACCEPT
    for dmz_ip in dmz_rules:
        _run_command(["/usr/sbin/iptables", "-A", chain_name, "-d", dmz_ip, "-j", "ACCEPT"])
        logger.info(f"Regla DMZ ACCEPT restaurada para {dmz_ip}")
    
    # ACCEPT incondicional final
    _run_command(["/usr/sbin/iptables", "-A", chain_name, "-j", "ACCEPT"])
    
    msg = f"Whitelist deshabilitada en VLAN {vlan_id}"
    logger.info(f"=== FIN: disable_whitelist ===")
    log_action("firewall", msg)
    
    return True, msg


def add_rule(params: Dict[str, Any] = None) -> Tuple[bool, str]:
    """Añadir regla a whitelist de una VLAN."""
    if not params or "vlan_id" not in params or "rule" not in params:
        return False, "Error: vlan_id y rule requeridos"
    
    # Validar VLAN ID
    valid, error = validate_vlan_id(params["vlan_id"])
    if not valid:
        return False, f"VLAN inválida: {error}"
    
    vlan_id = int(params["vlan_id"])
    
    rule = params["rule"].strip()
    
    # Validar que la regla es una IP válida
    valid, error = validate_ip_address(rule)
    if not valid:
        return False, f"Regla inválida '{rule}': {error}"
    
    fw_cfg = _load_firewall_config()
    
    if str(vlan_id) not in fw_cfg.get("vlans", {}):
        return False, f"VLAN {vlan_id} no encontrada"
    
    vlan_cfg = fw_cfg["vlans"][str(vlan_id)]
    
    if "whitelist" not in vlan_cfg:
        vlan_cfg["whitelist"] = []
    
    if rule in vlan_cfg["whitelist"]:
        return False, f"La regla ya existe en la whitelist"
    
    vlan_cfg["whitelist"].append(rule)
    _save_firewall_config(fw_cfg)
    
    # Reaplicar whitelist si está habilitada
    if vlan_cfg.get("whitelist_enabled", False):
        _apply_whitelist(vlan_id, vlan_cfg["whitelist"])
    
    msg = f"Regla añadida a VLAN {vlan_id}: {rule}"
    log_action("firewall", msg)
    
    return True, msg


def remove_rule(params: Dict[str, Any] = None) -> Tuple[bool, str]:
    """Eliminar regla de whitelist de una VLAN."""
    if not params or "vlan_id" not in params or "rule" not in params:
        return False, "Error: vlan_id y rule requeridos"
    
    try:
        vlan_id = int(params["vlan_id"])
    except (ValueError, TypeError):
        return False, f"Error: vlan_id debe ser entero"
    
    rule = params["rule"].strip()
    
    fw_cfg = _load_firewall_config()
    
    if str(vlan_id) not in fw_cfg.get("vlans", {}):
        return False, f"VLAN {vlan_id} no encontrada"
    
    vlan_cfg = fw_cfg["vlans"][str(vlan_id)]
    
    if "whitelist" not in vlan_cfg or rule not in vlan_cfg["whitelist"]:
        return False, f"La regla no existe en la whitelist"
    
    vlan_cfg["whitelist"].remove(rule)
    _save_firewall_config(fw_cfg)
    
    # Reaplicar whitelist si está habilitada
    if vlan_cfg.get("whitelist_enabled", False):
        _apply_whitelist(vlan_id, vlan_cfg["whitelist"])
    
    msg = f"Regla eliminada de VLAN {vlan_id}: {rule}"
    log_action("firewall", msg)
    
    return True, msg


def config(params: Dict[str, Any] = None) -> Tuple[bool, str]:
    """Configurar firewall (placeholder para la interfaz web)."""
    logger.info("Config llamado desde interfaz web")
    return True, "Use la interfaz web para configurar el firewall"


def reset_defaults(params: Dict[str, Any] = None) -> Tuple[bool, str]:
    """Restaurar firewall a valores por defecto y reiniciar."""
    logger.info("=== INICIO: reset_defaults ===")
    
    # FIX BUG #8: Detener DMZ primero para evitar inconsistencias
    try:
        from . import dmz
        dmz_success, dmz_msg = dmz.stop(params)
        if dmz_success:
            logger.info(f"DMZ detenido durante reset: {dmz_msg}")
        else:
            logger.warning(f"Error deteniendo DMZ durante reset: {dmz_msg}")
    except Exception as e:
        logger.warning(f"No se pudo detener DMZ durante reset: {e}")
    
    # Detener firewall
    stop(params)
    
    # Limpiar configuración
    fw_cfg = _load_firewall_config()
    for vlan_id in fw_cfg.get("vlans", {}).keys():
        fw_cfg["vlans"][vlan_id]["isolated"] = False
        fw_cfg["vlans"][vlan_id]["restricted"] = False
        fw_cfg["vlans"][vlan_id]["whitelist_enabled"] = False
        fw_cfg["vlans"][vlan_id]["whitelist"] = []
    
    _save_firewall_config(fw_cfg)
    
    # Reiniciar con políticas predeterminadas
    success, msg = start(params)
    
    logger.info("=== FIN: reset_defaults ===")
    return success, f"Firewall restaurado a valores por defecto\n{msg}"


# =============================================================================
# WHITELIST DE ACCIONES PERMITIDAS
# =============================================================================

ALLOWED_ACTIONS = {
    "start": start,
    "stop": stop,
    "restart": restart,
    "status": status,
    "aislar": aislar,
    "desaislar": desaislar,
    "restrict": restrict,
    "unrestrict": unrestrict,
    "enable_whitelist": enable_whitelist,
    "disable_whitelist": disable_whitelist,
    "add_rule": add_rule,
    "remove_rule": remove_rule,
    "reset_defaults": reset_defaults,
}
