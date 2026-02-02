# app/core/network_helpers.py
"""
Funciones auxiliares para operaciones de red comunes.
Incluye validación de VLANs, subredes, puertos, y operaciones bridge.
"""

import subprocess
import re
from typing import Dict, List, Optional, Tuple


# =============================================================================
# VALIDACIÓN DE VLAN
# =============================================================================

def validate_vlan_range(vlan_id: int, min_vlan: int = 1, max_vlan: int = 4094) -> Tuple[bool, str]:
    """
    Validar que un VLAN ID esté en el rango permitido.
    
    Args:
        vlan_id: ID de VLAN a validar
        min_vlan: VLAN mínima permitida (default: 1)
        max_vlan: VLAN máxima permitida (default: 4094)
    
    Returns:
        Tuple[valid, error_message]
    """
    if not isinstance(vlan_id, int):
        return False, f"VLAN ID debe ser integer, recibido {type(vlan_id).__name__}"
    
    if vlan_id < min_vlan or vlan_id > max_vlan:
        return False, f"VLAN ID debe estar entre {min_vlan} y {max_vlan}"
    
    return True, ""


def validate_vlan_name(name: str, max_length: int = 64) -> Tuple[bool, str]:
    """
    Validar nombre de VLAN.
    
    Args:
        name: Nombre del VLAN
        max_length: Longitud máxima permitida
    
    Returns:
        Tuple[valid, error_message]
    """
    if not name or not isinstance(name, str):
        return False, "Nombre de VLAN requerido"
    
    name = name.strip()
    if len(name) > max_length:
        return False, f"Nombre de VLAN muy largo (máx {max_length} caracteres)"
    
    # Permitir letras, números, guiones, guiones bajos
    if not re.match(r'^[a-zA-Z0-9_-]+$', name):
        return False, "Nombre de VLAN solo puede contener letras, números, guiones y guiones bajos"
    
    return True, ""


# =============================================================================
# VALIDACIÓN DE RED
# =============================================================================

def parse_cidr(cidr: str) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Parsear dirección CIDR en IP y máscara.
    
    Args:
        cidr: Dirección en formato CIDR (ej: 192.168.10.0/24)
    
    Returns:
        Tuple[valid, ip, mask_bits]
    """
    if not cidr or "/" not in cidr:
        return False, None, None
    
    try:
        parts = cidr.split("/")
        ip = parts[0].strip()
        mask_bits = parts[1].strip()
        
        # Validar que mask_bits es un número
        mask_int = int(mask_bits)
        if mask_int < 0 or mask_int > 32:
            return False, None, None
        
        return True, ip, mask_bits
    except:
        return False, None, None


def get_network_address(cidr: str) -> Optional[str]:
    """
    Obtener la dirección de red de una subnet CIDR.
    
    Args:
        cidr: Dirección en formato CIDR
    
    Returns:
        Dirección de red o None si es inválida
    """
    try:
        import ipaddress
        network = ipaddress.ip_network(cidr, strict=False)
        return str(network)
    except:
        return None


def get_broadcast_address(cidr: str) -> Optional[str]:
    """
    Obtener la dirección broadcast de una subnet CIDR.
    
    Args:
        cidr: Dirección en formato CIDR
    
    Returns:
        Dirección broadcast o None si es inválida
    """
    try:
        import ipaddress
        network = ipaddress.ip_network(cidr, strict=False)
        return str(network.broadcast_address)
    except:
        return None


def is_ip_in_subnet(ip: str, subnet: str) -> bool:
    """
    Verificar si una IP está dentro de una subnet.
    
    Args:
        ip: Dirección IP a verificar
        subnet: Subnet en formato CIDR
    
    Returns:
        True si la IP está en la subnet
    """
    try:
        import ipaddress
        return ipaddress.ip_address(ip) in ipaddress.ip_network(subnet, strict=False)
    except:
        return False


# =============================================================================
# VALIDACIÓN DE PUERTOS
# =============================================================================

def validate_port_range(port: int, min_port: int = 1, max_port: int = 65535) -> Tuple[bool, str]:
    """
    Validar que un puerto esté en el rango permitido.
    
    Args:
        port: Puerto a validar
        min_port: Puerto mínimo permitido
        max_port: Puerto máximo permitido
    
    Returns:
        Tuple[valid, error_message]
    """
    if not isinstance(port, int):
        return False, f"Puerto debe ser integer, recibido {type(port).__name__}"
    
    if port < min_port or port > max_port:
        return False, f"Puerto debe estar entre {min_port} y {max_port}"
    
    return True, ""


# =============================================================================
# OPERACIONES BRIDGE
# =============================================================================

def bridge_exists(bridge_name: str = "br0") -> bool:
    """
    Verificar si un bridge existe.
    
    Args:
        bridge_name: Nombre del bridge (default: br0)
    
    Returns:
        True si existe
    """
    try:
        result = subprocess.run(
            ["ip", "link", "show", bridge_name],
            capture_output=True,
            timeout=5,
            check=False
        )
        return result.returncode == 0
    except:
        return False


def get_bridge_members(bridge_name: str = "br0") -> List[str]:
    """
    Obtener las interfaces miembros de un bridge.
    
    Args:
        bridge_name: Nombre del bridge
    
    Returns:
        Lista de nombres de interfaz
    """
    try:
        result = subprocess.run(
            ["brctl", "show", bridge_name],
            capture_output=True,
            text=True,
            timeout=5,
            check=False
        )
        
        if result.returncode != 0:
            return []
        
        lines = result.stdout.strip().split("\n")
        if len(lines) < 2:
            return []
        
        # Primera línea es header, resto son interfaces
        members = []
        for line in lines[1:]:
            parts = line.split()
            if len(parts) >= 4:
                members.append(parts[0])
        
        return members
    except:
        return []


# =============================================================================
# OPERACIONES VLAN
# =============================================================================

def vlan_interface_exists(iface: str, vlan_id: int) -> bool:
    """
    Verificar si una interfaz VLAN existe.
    
    Args:
        iface: Interfaz base (ej: eth0)
        vlan_id: ID de VLAN
    
    Returns:
        True si existe
    """
    vlan_name = f"{iface}.{vlan_id}"
    try:
        result = subprocess.run(
            ["ip", "link", "show", vlan_name],
            capture_output=True,
            timeout=5,
            check=False
        )
        return result.returncode == 0
    except:
        return False


def get_interface_ip(iface: str) -> Optional[str]:
    """
    Obtener la dirección IP asignada a una interfaz.
    
    Args:
        iface: Nombre de la interfaz
    
    Returns:
        Dirección IP o None si no tiene
    """
    try:
        result = subprocess.run(
            ["ip", "addr", "show", iface],
            capture_output=True,
            text=True,
            timeout=5,
            check=False
        )
        
        if result.returncode != 0:
            return None
        
        # Buscar línea con "inet "
        for line in result.stdout.split("\n"):
            if "inet " in line:
                parts = line.strip().split()
                if len(parts) >= 2:
                    return parts[1].split("/")[0]
        
        return None
    except:
        return None


def is_interface_up(iface: str) -> bool:
    """
    Verificar si una interfaz está activa (UP).
    
    Args:
        iface: Nombre de la interfaz
    
    Returns:
        True si está UP
    """
    try:
        result = subprocess.run(
            ["ip", "link", "show", iface],
            capture_output=True,
            text=True,
            timeout=5,
            check=False
        )
        
        if result.returncode != 0:
            return False
        
        # Buscar "UP" en la primera línea
        first_line = result.stdout.split("\n")[0]
        return "UP" in first_line
    except:
        return False
