# app/core/helpers/helper_dmz.py
# Helper functions for DMZ module
# Extracted from app/core/dmz.py

import os
import logging
import ipaddress
from typing import Tuple, Optional
from datetime import datetime
from ...utils.helpers import load_json_config, save_json_config, run_command, write_log_file

logger = logging.getLogger(__name__)

# ==========================================
# Configuration
# ==========================================

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
CONFIG_FILE = os.path.join(BASE_DIR, "config", "dmz", "dmz.json")
WAN_CONFIG_FILE = os.path.join(BASE_DIR, "config", "wan", "wan.json")
VLANS_CONFIG_FILE = os.path.join(BASE_DIR, "config", "vlans", "vlans.json")
FIREWALL_CONFIG_FILE = os.path.join(BASE_DIR, "config", "firewall", "firewall.json")
LOG_FILE = os.path.join(BASE_DIR, "logs", "dmz", "actions.log")


# ==========================================
# Utility Functions
# ==========================================

def _run_command(cmd):
    """Alias para run_command."""
    return run_command(cmd)


def ensure_dirs():
    """Crear directorios necesarios."""
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    os.makedirs(os.path.join(BASE_DIR, "logs", "dmz"), exist_ok=True)


def write_log(message: str):
    """Escribir mensaje en el archivo de log."""
    ensure_dirs()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    write_log_file(LOG_FILE, f"[{timestamp}] {message}")


# ==========================================
# Configuration Loading
# ==========================================

def load_config() -> dict:
    """Cargar configuración de DMZ usando helpers."""
    cfg = load_json_config(CONFIG_FILE, {"status": 0, "destinations": []})
    return cfg if cfg else {"status": 0, "destinations": []}


def save_config(data: dict) -> None:
    """Guardar configuración de DMZ usando helpers."""
    save_json_config(CONFIG_FILE, data)


def load_wan_config() -> Optional[dict]:
    """Cargar configuración de WAN para obtener la interfaz usando helpers."""
    return load_json_config(WAN_CONFIG_FILE)


def load_firewall_config() -> Optional[dict]:
    """Cargar configuración del firewall usando helpers."""
    return load_json_config(FIREWALL_CONFIG_FILE)


def load_vlans_config() -> Optional[dict]:
    """Cargar configuración de VLANs usando helpers."""
    return load_json_config(VLANS_CONFIG_FILE)


def get_vlan_from_ip(ip: str) -> Optional[int]:
    """Determinar VLAN ID desde IP: busca en qué rango de VLAN cae la IP."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        
        # Cargar configuración de VLANs
        vlans_cfg = load_vlans_config()
        if not vlans_cfg:
            return None
        
        vlans = vlans_cfg.get("vlans", [])
        
        # Buscar en qué VLAN está esta IP
        for vlan in vlans:
            vlan_network_str = vlan.get("ip_network", "")
            if vlan_network_str:
                try:
                    vlan_network = ipaddress.ip_network(vlan_network_str, strict=False)
                    if ip_obj in vlan_network:
                        return vlan.get("id")
                except ValueError:
                    continue
        
        # Fallback a método antiguo (10.0.X.Y → X) para backward compatibility
        octets = str(ip_obj).split('.')
        if octets[0] == '10' and octets[1] == '0':
            return int(octets[2])
            
    except Exception as e:
        logger.error(f"Error determinando VLAN desde IP {ip}: {e}")
    
    return None


# ==========================================
# Chain Management
# ==========================================

def ensure_prerouting_protection_chain():
    """Crear cadena PREROUTING_PROTECTION en tabla NAT y garantizar que esté en posición 1 de PREROUTING.
    Esta cadena contiene reglas de aislamiento de hosts DMZ.
    """
    # Verificar si la cadena existe
    success, _ = _run_command(["/usr/sbin/iptables", "-t", "nat", "-L", "PREROUTING_PROTECTION", "-n"])
    
    if not success:
        _run_command(["/usr/sbin/iptables", "-t", "nat", "-N", "PREROUTING_PROTECTION"])
        logger.info("Cadena PREROUTING_PROTECTION creada en tabla NAT")
    
    # Verificar si está vinculada a PREROUTING
    success, _ = _run_command([
        "/usr/sbin/iptables", "-t", "nat", "-C", "PREROUTING", "-j", "PREROUTING_PROTECTION"
    ])
    
    if not success:
        # No está vinculada, vincular en posición 1
        _run_command(["/usr/sbin/iptables", "-t", "nat", "-I", "PREROUTING", "1", "-j", "PREROUTING_PROTECTION"])
        logger.info("Cadena PREROUTING_PROTECTION vinculada a PREROUTING en posición 1")
    else:
        # Ya está vinculada, verificar que esté en posición 1
        success, output = _run_command(["/usr/sbin/iptables", "-t", "nat", "-L", "PREROUTING", "-n", "--line-numbers"])
        if success:
            lines = output.strip().split('\n')
            for line in lines:
                if 'PREROUTING_PROTECTION' in line:
                    parts = line.split()
                    if parts and parts[0].isdigit():
                        position = int(parts[0])
                        if position != 1:
                            logger.warning(f"PREROUTING_PROTECTION en posición {position}, reposicionando a 1")
                            _run_command(["/usr/sbin/iptables", "-t", "nat", "-D", "PREROUTING", "-j", "PREROUTING_PROTECTION"])
                            _run_command(["/usr/sbin/iptables", "-t", "nat", "-I", "PREROUTING", "1", "-j", "PREROUTING_PROTECTION"])
                            logger.info("Cadena PREROUTING_PROTECTION reposicionada a posición 1")
                    break


def ensure_prerouting_vlan_chain(vlan_id: int) -> bool:
    """Crear cadena PREROUTING_VLAN_X en tabla nat si no existe y vincularla."""
    chain_name = f"PREROUTING_VLAN_{vlan_id}"
    
    # Verificar si la cadena existe
    success, _ = _run_command(["/usr/sbin/iptables", "-t", "nat", "-L", chain_name, "-n"])
    
    if not success:
        # Crear cadena
        success, output = _run_command(["/usr/sbin/iptables", "-t", "nat", "-N", chain_name])
        if not success:
            logger.error(f"Error creando {chain_name}: {output}")
            return False
        logger.info(f"Cadena {chain_name} creada")
    
    # Limpiar reglas existentes
    _run_command(["/usr/sbin/iptables", "-t", "nat", "-F", chain_name])
    
    # Verificar si está vinculada a PREROUTING
    success, _ = _run_command([
        "/usr/sbin/iptables", "-t", "nat", "-C", "PREROUTING", "-j", chain_name
    ])
    
    if not success:
        # Vincular a PREROUTING
        success, output = _run_command([
            "/usr/sbin/iptables", "-t", "nat", "-A", "PREROUTING", "-j", chain_name
        ])
        
        if not success:
            logger.error(f"Error vinculando {chain_name} a PREROUTING: {output}")
            return False
        
        logger.info(f"{chain_name} vinculada a PREROUTING")
    
    return True


def remove_prerouting_vlan_chain(vlan_id: int):
    """Desvincular y eliminar cadena PREROUTING_VLAN_X."""
    chain_name = f"PREROUTING_VLAN_{vlan_id}"
    
    # Desvincular desde PREROUTING (intentar múltiples veces por si hay duplicados)
    for attempt in range(5):
        success, _ = _run_command([
            "/usr/sbin/iptables", "-t", "nat", "-D", "PREROUTING", "-j", chain_name
        ])
        if not success:
            break
    
    # Limpiar y eliminar cadena
    _run_command(["/usr/sbin/iptables", "-t", "nat", "-F", chain_name])
    _run_command(["/usr/sbin/iptables", "-t", "nat", "-X", chain_name])
    
    logger.info(f"{chain_name} eliminada")


def add_forward_accept_rule(vlan_id: int, dmz_ip: str) -> bool:
    """Añadir regla ACCEPT para host DMZ en cadena FORWARD_VLAN_X.
    
    Verifica:
    1. Que la VLAN destino no esté aislada (Bug #1)
    2. Que no haya conflicto con whitelist activa (Bug #3)
    """
    chain_name = f"FORWARD_VLAN_{vlan_id}"
    
    # Verificar si la cadena existe
    success, _ = _run_command(["/usr/sbin/iptables", "-L", chain_name, "-n"])
    if not success:
        logger.warning(f"Cadena {chain_name} no existe, el firewall debe estar iniciado")
        return False
    
    # FIX BUG #1: Verificar si la VLAN destino del host DMZ está aislada
    dest_vlan_id = get_vlan_from_ip(dmz_ip)
    if dest_vlan_id:
        fw_cfg = load_firewall_config()
        if fw_cfg and str(dest_vlan_id) in fw_cfg.get("vlans", {}):
            if fw_cfg["vlans"][str(dest_vlan_id)].get("isolated", False):
                logger.error(f"No se puede añadir host DMZ {dmz_ip}: VLAN {dest_vlan_id} está aislada")
                logger.error(f"Desaísle la VLAN {dest_vlan_id} antes de configurar hosts DMZ en ella")
                return False
    
    # FIX BUG #3: Verificar conflicto con whitelist activa
    fw_cfg = load_firewall_config()
    if fw_cfg and str(vlan_id) in fw_cfg.get("vlans", {}):
        vlan_cfg = fw_cfg["vlans"][str(vlan_id)]
        if vlan_cfg.get("whitelist_enabled", False):
            whitelist = vlan_cfg.get("whitelist", [])
            # Extraer IPs de whitelist (formato puede ser IP, IP:puerto, IP/proto, etc)
            whitelist_ips = set()
            for rule in whitelist:
                # Extraer solo la IP (antes de : o /)
                ip_part = rule.split('/')[0].split(':')[0]
                if ip_part and ip_part != '':
                    whitelist_ips.add(ip_part)
            
            if dmz_ip not in whitelist_ips:
                logger.warning(f"⚠️ Host DMZ {dmz_ip} no está en whitelist de VLAN {vlan_id}")
                logger.warning(f"La regla DMZ ACCEPT se insertará ANTES de la whitelist, permitiendo acceso")
                logger.warning(f"Considere añadir {dmz_ip} a la whitelist para consistencia")
                # NO bloqueamos, solo advertimos. DMZ tiene prioridad sobre whitelist por diseño.
                # Si quisiera bloquear: return False
    
    # Verificar si la regla ya existe
    success, _ = _run_command([
        "/usr/sbin/iptables", "-C", chain_name, "-d", dmz_ip, "-j", "ACCEPT"
    ])
    
    if success:
        logger.info(f"Regla ACCEPT para {dmz_ip} ya existe en {chain_name}")
        return True
    
    # Insertar regla ACCEPT al inicio de la cadena (antes de whitelist/DROP)
    success, output = _run_command([
        "/usr/sbin/iptables", "-I", chain_name, "1", "-d", dmz_ip, "-j", "ACCEPT"
    ])
    
    if not success:
        logger.error(f"Error añadiendo ACCEPT para {dmz_ip} en {chain_name}: {output}")
        return False
    
    logger.info(f"Regla ACCEPT para {dmz_ip} añadida en {chain_name}")
    return True


def remove_forward_accept_rule(vlan_id: int, dmz_ip: str):
    """Eliminar regla ACCEPT para host DMZ de cadena FORWARD_VLAN_X."""
    chain_name = f"FORWARD_VLAN_{vlan_id}"
    
    # Intentar eliminar (puede no existir si firewall se detuvo)
    _run_command([
        "/usr/sbin/iptables", "-D", chain_name, "-d", dmz_ip, "-j", "ACCEPT"
    ])
    
    logger.info(f"Regla ACCEPT para {dmz_ip} eliminada de {chain_name}")


# ==========================================
# Validation & Checks
# ==========================================

def check_wan_configured() -> Tuple[bool, Optional[str]]:
    """Verificar si WAN está configurada y devolver interfaz."""
    wan_cfg = load_wan_config()
    if not wan_cfg:
        return False, None
    
    wan_interface = wan_cfg.get("interface")
    if not wan_interface:
        return False, None
    
    return True, wan_interface


def check_firewall_active() -> bool:
    """Verificar si el firewall está activo."""
    fw_cfg = load_firewall_config()
    if not fw_cfg:
        return False
    return fw_cfg.get("status", 0) == 1


def check_vlans_active() -> bool:
    """Verificar si hay VLANs activas."""
    vlans_cfg = load_vlans_config()
    if not vlans_cfg:
        return False
    return vlans_cfg.get("status", 0) == 1


def validate_destination(ip: str, port: int, protocol: str) -> Tuple[bool, str]:
    """Validar un destino DMZ.
    
    Verifica:
    1. IP es válida y privada (sin máscara, no termina en 0 o 255)
    2. Puerto válido (1-65535)
    3. Protocolo válido (tcp/udp)
    4. IP pertenece a una VLAN configurada
    5. IP está dentro del rango ip_network de la VLAN
    """
    # Validar que no contenga máscara de red
    if '/' in ip:
        return False, f"IP {ip} no debe contener máscara de red (/). Proporcione solo la IP del host."
    
    # Validar que no termine en 0 o 255
    ip_parts = ip.split('.')
    if len(ip_parts) == 4:
        try:
            last_octet = int(ip_parts[3])
            if last_octet == 0:
                return False, f"IP {ip} termina en 0 (dirección de red). Use una IP de host válida."
            if last_octet == 255:
                return False, f"IP {ip} termina en 255 (dirección de broadcast). Use una IP de host válida."
        except ValueError:
            pass  # Se capturará en la validación siguiente
    
    # Validar IP
    try:
        ip_obj = ipaddress.ip_address(ip)
        if not ip_obj.is_private:
            return False, f"IP {ip} no es una dirección privada válida"
    except ValueError:
        return False, f"IP {ip} no es válida"
    
    # Validar puerto
    if not (1 <= port <= 65535):
        return False, f"Puerto {port} no es válido (debe estar entre 1-65535)"
    
    # Validar protocolo
    if protocol not in ["tcp", "udp"]:
        return False, f"Protocolo {protocol} no es válido (debe ser tcp o udp)"
    
    # Validar que el host esté en una VLAN configurada
    vlan_id = get_vlan_from_ip(ip)
    if vlan_id is None:
        vlans_cfg = load_vlans_config()
        vlans = vlans_cfg.get("vlans", []) if vlans_cfg else []
        if vlans:
            vlan_networks = ", ".join([v.get("ip_network", "N/A") for v in vlans])
            return False, f"IP {ip} no está en ninguna VLAN configurada. VLANs disponibles: {vlan_networks}"
        else:
            return False, f"IP {ip} no está en ninguna VLAN. Configure VLANs primero."
    
    # Verificar que la VLAN existe en vlans.json y la IP está en su rango
    vlans_cfg = load_vlans_config()
    if not vlans_cfg:
        return False, "No se pudo cargar configuración de VLANs"
    
    vlans = vlans_cfg.get("vlans", [])
    vlan_found = None
    
    for vlan in vlans:
        if vlan.get("id") == vlan_id:
            vlan_found = vlan
            break
    
    if not vlan_found:
        return False, f"VLAN {vlan_id} no existe en el sistema. Configure la VLAN primero."
    
    # MEJORA: Verificar que la IP está dentro del rango ip_network de la VLAN
    vlan_network_str = vlan_found.get("ip_network", "")
    if not vlan_network_str:
        logger.warning(f"VLAN {vlan_id} no tiene ip_network configurado")
        return False, f"VLAN {vlan_id} no tiene rango de red configurado"
    
    try:
        vlan_network = ipaddress.ip_network(vlan_network_str, strict=False)
        
        # Verificar que la IP está dentro del rango
        if ip_obj not in vlan_network:
            return False, (f"IP {ip} no pertenece al rango de VLAN {vlan_id} "
                          f"({vlan_network_str}). "
                          f"Rango válido: {vlan_network.network_address + 1} - "
                          f"{vlan_network.broadcast_address - 1}")
        
        # Verificar que no es la dirección de red ni broadcast
        if ip_obj == vlan_network.network_address:
            return False, f"IP {ip} es la dirección de red de VLAN {vlan_id} (no válida para host)"
        
        if ip_obj == vlan_network.broadcast_address:
            return False, f"IP {ip} es la dirección de broadcast de VLAN {vlan_id} (no válida para host)"
        
        # Verificar que no es la IP del router (gateway)
        vlan_ip_interface = vlan_found.get("ip_interface", "")
        if vlan_ip_interface:
            try:
                gateway_ip = ipaddress.ip_interface(vlan_ip_interface).ip
                if ip_obj == gateway_ip:
                    return False, f"IP {ip} es la IP del router/gateway de VLAN {vlan_id} (no válida para DMZ)"
            except Exception:
                pass  # Si no se puede parsear, continuar
        
        logger.debug(f"IP {ip} validada correctamente en VLAN {vlan_id} ({vlan_network_str})")
        
    except Exception as e:
        logger.error(f"Error validando rango de red para VLAN {vlan_id}: {e}")
        return False, f"Error al validar rango de red: {str(e)}"
    
    return True, ""
