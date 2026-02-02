#!/usr/bin/env python3
"""
Validadores centralizados para JSBach V4.0
Proporciona funciones de validación reutilizables para todos los módulos
"""

import re
import ipaddress
from typing import Tuple, Any, List, Dict
import logging

logger = logging.getLogger(__name__)

# Patrones de validación
INTERFACE_PATTERN = r"^[a-zA-Z0-9._-]+$"
PROTOCOL_PATTERN = r"^(tcp|udp|icmp|all)$"
ACTION_PATTERN = r"^(add|remove|delete|show|config|update)$"

class ValidationError(Exception):
    """Excepción personalizada para errores de validación"""
    pass


def validate_vlan_id(vlan_id: Any) -> Tuple[bool, str]:
    """
    Validar VLAN ID está en rango válido [1, 4094]
    
    Args:
        vlan_id: ID a validar (puede ser int, str, etc.)
    
    Returns:
        (válido, mensaje_error)
    """
    try:
        vid = int(vlan_id)
        if not (1 <= vid <= 4094):
            return False, f"VLAN ID {vid} fuera de rango [1, 4094]"
        return True, ""
    except (ValueError, TypeError):
        return False, f"VLAN ID inválido: {vlan_id} (tipo: {type(vlan_id).__name__})"


def validate_port(port: Any, allow_zero: bool = False) -> Tuple[bool, str]:
    """
    Validar puerto está en rango válido
    
    Args:
        port: Puerto a validar
        allow_zero: Si True, permite puerto 0
    
    Returns:
        (válido, mensaje_error)
    """
    try:
        p = int(port)
        min_port = 0 if allow_zero else 1
        max_port = 65535
        
        if not (min_port <= p <= max_port):
            return False, f"Puerto {p} fuera de rango [{min_port}, {max_port}]"
        return True, ""
    except (ValueError, TypeError):
        return False, f"Puerto inválido: {port} (tipo: {type(port).__name__})"


def validate_ip_address(ip: str, allow_ipv6: bool = True) -> Tuple[bool, str]:
    """
    Validar dirección IP (v4 o v6)
    
    Args:
        ip: Dirección IP a validar
        allow_ipv6: Si True, permite direcciones IPv6
    
    Returns:
        (válido, mensaje_error)
    """
    try:
        addr = ipaddress.ip_address(ip)
        
        if isinstance(addr, ipaddress.IPv6Address) and not allow_ipv6:
            return False, f"IPv6 no permitido: {ip}"
        
        return True, ""
    except (ValueError, ipaddress.AddressValueError):
        return False, f"Dirección IP inválida: {ip}"


def validate_ip_network(network: str) -> Tuple[bool, str]:
    """
    Validar red IP (CIDR notation)
    
    Args:
        network: Red a validar (ej: "192.168.1.0/24")
    
    Returns:
        (válido, mensaje_error)
    """
    try:
        ipaddress.ip_network(network, strict=False)
        return True, ""
    except (ValueError, ipaddress.NetmaskValueError):
        return False, f"Red IP inválida: {network}"


def validate_interface_name(interface: str) -> Tuple[bool, str]:
    """
    Validar nombre de interfaz de red
    
    Args:
        interface: Nombre de interfaz (ej: "eth0", "vlan10")
    
    Returns:
        (válido, mensaje_error)
    """
    if not interface or not isinstance(interface, str):
        return False, f"Nombre de interfaz inválido: {interface}"
    
    if not re.match(INTERFACE_PATTERN, interface):
        return False, f"Nombre de interfaz contiene caracteres inválidos: {interface}"
    
    if len(interface) > 15:  # Límite de Linux
        return False, f"Nombre de interfaz demasiado largo (máx 15): {interface}"
    
    return True, ""


def sanitize_interface_name(name: str) -> bool:
    """
    Validar que el nombre de interfaz sea seguro (solo alfanuméricos, puntos, guiones, guiones bajos).
    Versión simplificada de validate_interface_name que retorna bool.
    
    Args:
        name: Nombre de interfaz a validar
    
    Returns:
        True si el nombre es seguro, False en caso contrario
    """
    if not name or not isinstance(name, str):
        return False
    return bool(re.match(INTERFACE_PATTERN, name))


def validate_protocol(protocol: str) -> Tuple[bool, str]:
    """
    Validar protocolo de red
    
    Args:
        protocol: Protocolo (tcp, udp, icmp, all, etc.)
    
    Returns:
        (válido, mensaje_error)
    """
    if not protocol or not isinstance(protocol, str):
        return False, f"Protocolo inválido: {protocol}"
    
    protocol_lower = protocol.lower()
    
    if not re.match(PROTOCOL_PATTERN, protocol_lower):
        return False, f"Protocolo no soportado: {protocol}"
    
    return True, ""


def validate_action(action: str) -> Tuple[bool, str]:
    """
    Validar acción de configuración
    
    Args:
        action: Acción (add, remove, show, etc.)
    
    Returns:
        (válido, mensaje_error)
    """
    if not action or not isinstance(action, str):
        return False, f"Acción inválida: {action}"
    
    if not re.match(ACTION_PATTERN, action.lower()):
        return False, f"Acción no soportada: {action}"
    
    return True, ""


def validate_vlan_range_string(vlan_string: str) -> Tuple[bool, str, List[int]]:
    """
    Validar string de rango de VLANs (ej: "1,2,3-10,12,14-15")
    
    Args:
        vlan_string: String con VLANs
    
    Returns:
        (válido, mensaje_error, lista_vlans)
    """
    if not vlan_string or not isinstance(vlan_string, str):
        return False, f"String de VLAN inválido: {vlan_string}", []
    
    # Rechazar espacios
    if ' ' in vlan_string:
        return False, "No se permiten espacios en el string de VLANs", []
    
    vlans = set()
    
    try:
        parts = vlan_string.split(',')
        
        for part in parts:
            part = part.strip()
            if not part:
                continue
            
            if '-' in part:
                # Rango
                range_parts = part.split('-')
                if len(range_parts) != 2:
                    return False, f"Rango inválido: {part}", []
                
                try:
                    start = int(range_parts[0])
                    end = int(range_parts[1])
                except ValueError:
                    return False, f"VLAN ID no numérico en rango: {part}", []
                
                # Validar cada VLAN en el rango
                for vid in range(start, end + 1):
                    valid, _ = validate_vlan_id(vid)
                    if not valid:
                        return False, f"VLAN ID {vid} fuera de rango en: {part}", []
                    vlans.add(vid)
            else:
                # VLAN individual
                try:
                    vid = int(part)
                except ValueError:
                    return False, f"VLAN ID no numérico: {part}", []
                
                valid, error = validate_vlan_id(vid)
                if not valid:
                    return False, f"VLAN {part}: {error}", []
                
                vlans.add(vid)
        
        if not vlans:
            return False, "No se especificaron VLANs válidas", []
        
        return True, "", sorted(list(vlans))
    
    except Exception as e:
        return False, f"Error parsing VLANs: {str(e)}", []


def normalize_bool(value: Any) -> bool:
    """
    Normalizar cualquier tipo a bool
    
    Args:
        value: Valor a normalizar
    
    Returns:
        Valor booleano
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return bool(value)
    if isinstance(value, str):
        return value.lower() in ("true", "1", "yes", "on", "enabled", "active")
    return False


def normalize_int(value: Any, min_val: int = None, max_val: int = None) -> int:
    """
    Normalizar a int con validación de rango opcional
    
    Args:
        value: Valor a normalizar
        min_val: Valor mínimo (opcional)
        max_val: Valor máximo (opcional)
    
    Returns:
        Valor como integer
    
    Raises:
        ValidationError: Si el valor no es válido
    """
    try:
        v = int(value)
        if min_val is not None and v < min_val:
            raise ValidationError(f"Valor {v} menor que mínimo {min_val}")
        if max_val is not None and v > max_val:
            raise ValidationError(f"Valor {v} mayor que máximo {max_val}")
        return v
    except (ValueError, TypeError) as e:
        raise ValidationError(f"Valor no puede convertirse a int: {value}")


def sanitize_for_log(data: Any, max_len: int = 100) -> str:
    """
    Sanitizar datos antes de escribir en logs
    
    Remueve caracteres de control y limita longitud
    
    Args:
        data: Datos a sanitizar
        max_len: Longitud máxima
    
    Returns:
        String sanitizado
    """
    try:
        if isinstance(data, str):
            # Remover caracteres de control, limitar longitud
            safe = ''.join(
                c if c.isprintable() and c not in '\n\r\t' 
                else f'[0x{ord(c):02x}]' 
                for c in data
            )
            return safe[:max_len]
        return str(data)[:max_len]
    except Exception:
        return "[ERROR_SANITIZING]"


def validate_dict_required_keys(data: Dict, required_keys: List[str]) -> Tuple[bool, str]:
    """
    Validar que un diccionario tiene todas las claves requeridas
    
    Args:
        data: Diccionario a validar
        required_keys: Lista de claves requeridas
    
    Returns:
        (válido, mensaje_error)
    """
    if not isinstance(data, dict):
        return False, f"Datos no son un diccionario"
    
    missing = set(required_keys) - set(data.keys())
    if missing:
        return False, f"Claves requeridas faltantes: {', '.join(missing)}"
    
    return True, ""


def validate_enum(value: Any, allowed_values: List[Any], case_insensitive: bool = False) -> Tuple[bool, str]:
    """
    Validar que un valor está en una lista de valores permitidos
    
    Args:
        value: Valor a validar
        allowed_values: Lista de valores permitidos
        case_insensitive: Si True, compara sin considerar mayúsculas
    
    Returns:
        (válido, mensaje_error)
    """
    if case_insensitive and isinstance(value, str):
        check_value = value.lower()
        allowed_lower = [v.lower() if isinstance(v, str) else v for v in allowed_values]
        if check_value not in allowed_lower:
            return False, f"Valor '{value}' no está en lista permitida: {allowed_values}"
    else:
        if value not in allowed_values:
            return False, f"Valor '{value}' no está en lista permitida: {allowed_values}"
    
    return True, ""


# Función auxiliar para validación en batch
def validate_params(params: Dict, required: Dict[str, str]) -> Tuple[bool, Dict[str, str]]:
    """
    Validar múltiples parámetros según tipo especificado
    
    Args:
        params: Diccionario con parámetros
        required: Dict {nombre: tipo} donde tipo es:
                  "vlan_id", "port", "ip", "network", "interface", 
                  "protocol", "action", "bool", "int", "str"
    
    Returns:
        (válido, errores_dict)
    """
    errors = {}
    
    for key, vtype in required.items():
        if key not in params:
            errors[key] = "Parámetro requerido"
            continue
        
        value = params[key]
        valid = True
        error_msg = ""
        
        if vtype == "vlan_id":
            valid, error_msg = validate_vlan_id(value)
        elif vtype == "port":
            valid, error_msg = validate_port(value)
        elif vtype == "ip":
            valid, error_msg = validate_ip_address(value)
        elif vtype == "network":
            valid, error_msg = validate_ip_network(value)
        elif vtype == "interface":
            valid, error_msg = validate_interface_name(value)
        elif vtype == "protocol":
            valid, error_msg = validate_protocol(value)
        elif vtype == "action":
            valid, error_msg = validate_action(value)
        elif vtype == "bool":
            normalize_bool(value)  # No lanza error, siempre válido
        elif vtype == "int":
            try:
                int(value)
            except (ValueError, TypeError):
                valid, error_msg = False, "No es un número entero"
        elif vtype == "str":
            if not isinstance(value, str):
                valid, error_msg = False, "No es un string"
        
        if not valid:
            errors[key] = error_msg
    
    return len(errors) == 0, errors


if __name__ == "__main__":
    # Tests simples
    print("Testing validators...")
    
    # VLAN ID
    assert validate_vlan_id(10) == (True, "")
    assert validate_vlan_id(5000) == (False, "VLAN ID 5000 fuera de rango [1, 4094]")
    
    # Port
    assert validate_port(80) == (True, "")
    assert validate_port(70000) == (False, "Puerto 70000 fuera de rango [1, 65535]")
    
    # IP
    assert validate_ip_address("192.168.1.1") == (True, "")
    assert validate_ip_address("999.999.999.999") == (False, "Dirección IP inválida: 999.999.999.999")
    
    # Interface
    assert validate_interface_name("eth0") == (True, "")
    assert validate_interface_name("eth 0") == (False, "Nombre de interfaz contiene caracteres inválidos: eth 0")
    
    # VLAN Range
    valid, error, vlans = validate_vlan_range_string("1,2,3-10,12,14-15")
    assert valid and vlans == [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 14, 15]
    
    valid, error, vlans = validate_vlan_range_string("1, 2, 3")  # Con espacios
    assert not valid
    
    print("✅ Todos los tests pasaron!")
