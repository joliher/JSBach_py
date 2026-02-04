# app/core/helpers/helper_firewall.py
# Helper functions for Firewall module
# Extracted from app/core/firewall.py

import os
import re
import json
import logging
from typing import Tuple, List
from ...utils.global_functions import create_module_log_directory, create_module_config_directory
from ...utils.helpers import load_json_config, save_json_config, run_command

logger = logging.getLogger(__name__)

# ==========================================
# Configuration
# ==========================================

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
FIREWALL_CONFIG_FILE = os.path.join(BASE_DIR, "config", "firewall", "firewall.json")
VLANS_CONFIG_FILE = os.path.join(BASE_DIR, "config", "vlans", "vlans.json")
WAN_CONFIG_FILE = os.path.join(BASE_DIR, "config", "wan", "wan.json")


# ==========================================
# Utility Functions
# ==========================================

def ensure_dirs():
    """Crear directorios necesarios para configuración y logs."""
    os.makedirs(os.path.dirname(FIREWALL_CONFIG_FILE), exist_ok=True)
    create_module_log_directory("firewall")
    create_module_config_directory("firewall")


def _run_command(cmd):
    """Alias para run_command."""
    return run_command(cmd)


# ==========================================
# Configuration Loading
# ==========================================

def load_firewall_config():
    """Load firewall configuration."""
    return load_json_config(FIREWALL_CONFIG_FILE, {"vlans": {}, "status": 0})


def load_vlans_config():
    """Load VLANS configuration."""
    return load_json_config(VLANS_CONFIG_FILE, {"vlans": [], "status": 0})


def load_wan_config():
    """Load WAN configuration."""
    return load_json_config(WAN_CONFIG_FILE)


def save_firewall_config(data):
    """Save firewall configuration."""
    return save_json_config(FIREWALL_CONFIG_FILE, data)


def check_wan_configured() -> bool:
    """Verificar si la WAN está configurada (tiene interfaz asignada)."""
    wan_cfg = load_wan_config()
    if not wan_cfg:
        return False
    return bool(wan_cfg.get("interface"))


# ==========================================
# Chain Management
# ==========================================

def ensure_input_protection_chain():
    """Crear cadena INPUT_PROTECTION y garantizar que esté en posición 1 de INPUT.
    Esta cadena protege el router desde WAN.
    """
    # Verificar si la cadena existe
    success, _ = _run_command(["/usr/sbin/iptables", "-L", "INPUT_PROTECTION", "-n"])
    
    if not success:
        _run_command(["/usr/sbin/iptables", "-N", "INPUT_PROTECTION"])
        logger.info("Cadena INPUT_PROTECTION creada")
    
    # Verificar si está vinculada a INPUT
    success, _ = _run_command([
        "/usr/sbin/iptables", "-C", "INPUT", "-j", "INPUT_PROTECTION"
    ])
    
    if not success:
        # No está vinculada, vincular en posición 1
        _run_command(["/usr/sbin/iptables", "-I", "INPUT", "1", "-j", "INPUT_PROTECTION"])
        logger.info("Cadena INPUT_PROTECTION vinculada a INPUT en posición 1")
    else:
        # Ya está vinculada, verificar que esté en posición 1
        success, output = _run_command(["/usr/sbin/iptables", "-L", "INPUT", "-n", "--line-numbers"])
        if success:
            lines = output.strip().split('\n')
            for line in lines:
                if 'INPUT_PROTECTION' in line:
                    # Usar regex para extraer número de posición (más robusto)
                    match = re.match(r'^(\d+)\s+', line)
                    if match:
                        position = int(match.group(1))
                        if position != 1:
                            logger.warning(f"INPUT_PROTECTION en posición {position}, reposicionando a 1")
                            _run_command(["/usr/sbin/iptables", "-D", "INPUT", "-j", "INPUT_PROTECTION"])
                            _run_command(["/usr/sbin/iptables", "-I", "INPUT", "1", "-j", "INPUT_PROTECTION"])
                            logger.info("Cadena INPUT_PROTECTION reposicionada a posición 1")
                    break


def ensure_forward_protection_chain():
    """Crear cadena FORWARD_PROTECTION y garantizar que esté en posición 1 de FORWARD.
    Esta cadena contiene reglas de aislamiento de VLANs.
    """
    # Verificar si la cadena existe
    success, _ = _run_command(["/usr/sbin/iptables", "-L", "FORWARD_PROTECTION", "-n"])
    
    if not success:
        _run_command(["/usr/sbin/iptables", "-N", "FORWARD_PROTECTION"])
        logger.info("Cadena FORWARD_PROTECTION creada")
    
    # Verificar si está vinculada a FORWARD
    success, _ = _run_command([
        "/usr/sbin/iptables", "-C", "FORWARD", "-j", "FORWARD_PROTECTION"
    ])
    
    if not success:
        # No está vinculada, vincular en posición 1
        _run_command(["/usr/sbin/iptables", "-I", "FORWARD", "1", "-j", "FORWARD_PROTECTION"])
        logger.info("Cadena FORWARD_PROTECTION vinculada a FORWARD en posición 1")
    else:
        # Ya está vinculada, verificar que esté en posición 1
        success, output = _run_command(["/usr/sbin/iptables", "-L", "FORWARD", "-n", "--line-numbers"])
        if success:
            lines = output.strip().split('\n')
            for line in lines:
                if 'FORWARD_PROTECTION' in line:
                    # Usar regex para extraer número de posición (más robusto)
                    match = re.match(r'^(\d+)\s+', line)
                    if match:
                        position = int(match.group(1))
                        if position != 1:
                            logger.warning(f"FORWARD_PROTECTION en posición {position}, reposicionando a 1")
                            _run_command(["/usr/sbin/iptables", "-D", "FORWARD", "-j", "FORWARD_PROTECTION"])
                            _run_command(["/usr/sbin/iptables", "-I", "FORWARD", "1", "-j", "FORWARD_PROTECTION"])
                            logger.info("Cadena FORWARD_PROTECTION reposicionada a posición 1")
                    break


def setup_wan_protection():
    """Configurar protección del router desde WAN (solo ICMP permitido)."""
    wan_cfg = load_wan_config()
    if not wan_cfg or not wan_cfg.get("interface"):
        return
    
    wan_interface = wan_cfg["interface"]
    
    # Limpiar cadena INPUT_PROTECTION
    _run_command(["/usr/sbin/iptables", "-F", "INPUT_PROTECTION"])
    
    # Permitir ICMP desde WAN
    _run_command([
        "/usr/sbin/iptables", "-A", "INPUT_PROTECTION", "-i", wan_interface, 
        "-p", "icmp", "-j", "ACCEPT"
    ])
    
    # Bloquear todo lo demás desde WAN
    _run_command([
        "/usr/sbin/iptables", "-A", "INPUT_PROTECTION", "-i", wan_interface, "-j", "DROP"
    ])
    
    logger.info(f"Protección WAN configurada en {wan_interface}")


# ==========================================
# VLAN Chain Management
# ==========================================

def create_input_vlan_chain(vlan_id: int, vlan_ip: str) -> bool:
    """Crear cadena INPUT_VLAN_X y vincularla desde INPUT."""
    chain_name = f"INPUT_VLAN_{vlan_id}"
    
    # Crear cadena
    success, output = _run_command(["/usr/sbin/iptables", "-N", chain_name])
    if not success and "already exists" not in output.lower():
        logger.error(f"Error creando {chain_name}: {output}")
        return False
    
    # Limpiar reglas existentes
    _run_command(["/usr/sbin/iptables", "-F", chain_name])
    
    # Vincular desde INPUT (después de INPUT_PROTECTION)
    # Verificar si ya está vinculada
    success, _ = _run_command([
        "/usr/sbin/iptables", "-C", "INPUT", "-s", vlan_ip, "-j", chain_name
    ])
    
    if not success:
        # No está vinculada, añadir después de INPUT_PROTECTION (posición 2)
        _run_command([
            "/usr/sbin/iptables", "-I", "INPUT", "2", "-s", vlan_ip, "-j", chain_name
        ])
        logger.info(f"{chain_name} vinculada desde INPUT")
    
    return True


def create_forward_vlan_chain(vlan_id: int, vlan_ip: str) -> bool:
    """Crear cadena FORWARD_VLAN_X y vincularla desde FORWARD."""
    chain_name = f"FORWARD_VLAN_{vlan_id}"
    
    # Crear cadena
    success, output = _run_command(["/usr/sbin/iptables", "-N", chain_name])
    if not success and "already exists" not in output.lower():
        logger.error(f"Error creando {chain_name}: {output}")
        return False
    
    # Limpiar reglas existentes
    _run_command(["/usr/sbin/iptables", "-F", chain_name])
    
    # Por defecto: ACCEPT todo (sin whitelist)
    _run_command(["/usr/sbin/iptables", "-A", chain_name, "-j", "ACCEPT"])
    
    # Vincular desde FORWARD (después de FORWARD_PROTECTION)
    # Verificar si ya está vinculada
    success, _ = _run_command([
        "/usr/sbin/iptables", "-C", "FORWARD", "-s", vlan_ip, "-j", chain_name
    ])
    
    if not success:
        # No está vinculada, añadir después de FORWARD_PROTECTION (posición 2)
        _run_command([
            "/usr/sbin/iptables", "-I", "FORWARD", "2", "-s", vlan_ip, "-j", chain_name
        ])
        logger.info(f"{chain_name} vinculada desde FORWARD")
    
    return True


def remove_input_vlan_chain(vlan_id: int, vlan_ip: str):
    """Desvincular y eliminar cadena INPUT_VLAN_X."""
    chain_name = f"INPUT_VLAN_{vlan_id}"
    
    # Desvincular desde INPUT
    _run_command([
        "/usr/sbin/iptables", "-D", "INPUT", "-s", vlan_ip, "-j", chain_name
    ])
    
    # Limpiar y eliminar cadena
    _run_command(["/usr/sbin/iptables", "-F", chain_name])
    _run_command(["/usr/sbin/iptables", "-X", chain_name])
    
    logger.info(f"{chain_name} eliminada")


def remove_forward_vlan_chain(vlan_id: int, vlan_ip: str):
    """Desvincular y eliminar cadena FORWARD_VLAN_X."""
    chain_name = f"FORWARD_VLAN_{vlan_id}"
    
    # Desvincular desde FORWARD
    _run_command([
        "/usr/sbin/iptables", "-D", "FORWARD", "-s", vlan_ip, "-j", chain_name
    ])
    
    # Limpiar y eliminar cadena
    _run_command(["/usr/sbin/iptables", "-F", chain_name])
    _run_command(["/usr/sbin/iptables", "-X", chain_name])
    
    logger.info(f"{chain_name} eliminada")


# ==========================================
# Whitelist Management
# ==========================================

def apply_whitelist(vlan_id: int, whitelist: List[str]) -> Tuple[bool, str]:
    """Aplicar whitelist en cadena FORWARD_VLAN_X.
    
    Formatos soportados:
    - IP: 8.8.8.8
    - IP/proto: 8.8.8.8/tcp
    - IP:puerto: 192.168.1.1:80
    - IP:puerto/proto: 8.8.8.8:53/udp
    - :puerto: :443
    - :puerto/proto: :22/tcp
    """
    chain_name = f"FORWARD_VLAN_{vlan_id}"
    
    # FIX BUG #6: Preservar reglas DMZ ACCEPT antes de limpiar
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
    
    # Buscar reglas ACCEPT con IPs DMZ reales
    dmz_rules = []
    success, output = _run_command(["/usr/sbin/iptables", "-L", chain_name, "-n", "--line-numbers"])
    if success:
        for line in output.split('\n'):
            # Buscar reglas ACCEPT con destino específico usando regex
            if 'ACCEPT' in line:
                # Usar regex para extraer IP destino (más robusto que posiciones)
                # Patrón: buscar "ACCEPT" seguido de destino IP (no 0.0.0.0/0)
                match = re.search(r'\s+([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(?:/\d+)?)\s+', line)
                if match:
                    dest_ip = match.group(1)
                    # Solo preservar si no es 0.0.0.0/0 y está en dmz_ips
                    if dest_ip != '0.0.0.0/0' and dest_ip in dmz_ips:
                        dmz_rules.append(dest_ip)
                        logger.info(f"Preservando regla DMZ ACCEPT para {dest_ip}")
    
    # Limpiar cadena
    _run_command(["/usr/sbin/iptables", "-F", chain_name])
    
    # Re-añadir reglas DMZ ACCEPT al inicio
    for dmz_ip in dmz_rules:
        _run_command(["/usr/sbin/iptables", "-A", chain_name, "-d", dmz_ip, "-j", "ACCEPT"])
        logger.info(f"Regla DMZ ACCEPT restaurada para {dmz_ip}")
    
    if not whitelist:
        # Sin reglas, DROP por defecto
        _run_command(["/usr/sbin/iptables", "-A", chain_name, "-j", "DROP"])
        return True, "Whitelist vacía, todo bloqueado"
    
    for rule in whitelist:
        success = apply_single_whitelist_rule(chain_name, rule)
        if not success:
            logger.warning(f"Error aplicando regla whitelist: {rule}")
    
    # DROP final para bloquear todo lo no permitido
    # Nota: No verificamos si existe porque apply_whitelist siempre hace FLUSH antes
    _run_command(["/usr/sbin/iptables", "-A", chain_name, "-j", "DROP"])
    logger.debug(f"Regla DROP añadida al final de {chain_name}")
    
    return True, f"Whitelist aplicada con {len(whitelist)} reglas"


def apply_single_whitelist_rule(chain_name: str, rule: str) -> bool:
    """Aplicar una regla de whitelist individual."""
    try:
        # Parsear regla: IP[:puerto][/proto]
        ip = None
        port = None
        protocol = None
        
        if "/" in rule:
            rule, protocol = rule.rsplit("/", 1)
        
        if ":" in rule:
            ip, port = rule.split(":", 1)
            if not ip:  # :puerto
                ip = None
        else:
            ip = rule if rule else None
        
        # Construir comandos para verificación y adición
        if port and protocol:
            # Caso: IP:puerto/proto o :puerto/proto
            check_cmd = ["/usr/sbin/iptables", "-C", chain_name]
            add_cmd = ["/usr/sbin/iptables", "-A", chain_name]
            
            if ip:
                check_cmd.extend(["-d", ip])
                add_cmd.extend(["-d", ip])
            
            check_cmd.extend(["-p", protocol, "--dport", port, "-j", "ACCEPT"])
            add_cmd.extend(["-p", protocol, "--dport", port, "-j", "ACCEPT"])
            
            success, _ = _run_command(check_cmd)
            if not success:
                _run_command(add_cmd)
            
        elif port:
            # Caso: IP:puerto o :puerto (sin protocolo → TCP + UDP)
            for proto in ["tcp", "udp"]:
                check_cmd = ["/usr/sbin/iptables", "-C", chain_name]
                add_cmd = ["/usr/sbin/iptables", "-A", chain_name]
                
                if ip:
                    check_cmd.extend(["-d", ip])
                    add_cmd.extend(["-d", ip])
                
                check_cmd.extend(["-p", proto, "--dport", port, "-j", "ACCEPT"])
                add_cmd.extend(["-p", proto, "--dport", port, "-j", "ACCEPT"])
                
                success, _ = _run_command(check_cmd)
                if not success:
                    _run_command(add_cmd)
                    
        elif protocol and ip:
            # Caso: IP/proto (sin puerto)
            check_cmd = ["/usr/sbin/iptables", "-C", chain_name, "-d", ip, "-p", protocol, "-j", "ACCEPT"]
            add_cmd = ["/usr/sbin/iptables", "-A", chain_name, "-d", ip, "-p", protocol, "-j", "ACCEPT"]
            
            success, _ = _run_command(check_cmd)
            if not success:
                _run_command(add_cmd)
                
        elif ip:
            # Caso: solo IP (sin puerto ni protocolo)
            check_cmd = ["/usr/sbin/iptables", "-C", chain_name, "-d", ip, "-j", "ACCEPT"]
            add_cmd = ["/usr/sbin/iptables", "-A", chain_name, "-d", ip, "-j", "ACCEPT"]
            
            success, _ = _run_command(check_cmd)
            if not success:
                _run_command(add_cmd)
        else:
            # Caso: :puerto (sin IP ni protocolo, ya manejado arriba)
            logger.warning(f"Regla malformada: {rule}")
            return False
        
        return True
        
    except Exception as e:
        logger.error(f"Error parseando regla whitelist '{rule}': {e}")
        return False
