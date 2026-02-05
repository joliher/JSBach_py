# app/core/helpers/helper_expect.py
"""Helper functions for the Expect module (Remote Switch Config)."""

import os
import re
import json
from typing import Tuple, List, Dict, Any, Optional
from ...utils.helpers.module_helpers import run_command
from ...utils.validators import validate_ip_address

def check_ip_reachability(ip: str) -> bool:
    """Checks if an IP is reachable via ICMP (ping)."""
    success, _ = run_command(["/usr/bin/ping", "-c", "1", "-W", "2", ip], use_sudo=False)
    return success

def _clean_range_string(s: str) -> str:
    """Removes spaces and validates basic characters for a range string."""
    if not s:
        return ""
    # Remove all spaces
    s = s.replace(" ", "")
    # Basic character check (numbers, commas, dashes)
    if not re.match(r'^[0-9,\-]+$', s):
        return None
    return s

def validate_port_range(ports_str: str, max_ports: int = 48) -> Tuple[bool, List[int], str]:
    """
    Validates a port string (e.g., '1-4', '1,3,5', '1-4,6').
    Supports spaces: '1, 2-3' -> [1,2,3]
    Returns: (is_valid, list_of_ports, error_msg)
    """
    cleaned = _clean_range_string(ports_str)
    if cleaned is None:
        return False, [], f"Caracteres inválidos en el rango de puertos: {ports_str}"
    if not cleaned:
        return False, [], "El campo de puertos está vacío"
    
    ports = set()
    parts = cleaned.split(',')
    for part in parts:
        if not part: continue
        if '-' in part:
            try:
                start_str, end_str = part.split('-', 1)
                start, end = int(start_str), int(end_str)
                if start > end:
                    return False, [], f"Rango inválido: {start}-{end}"
                for p in range(start, end + 1):
                    ports.add(p)
            except ValueError:
                return False, [], f"Valor numérico inválido en rango: {part}"
        else:
            try:
                ports.add(int(part))
            except ValueError:
                return False, [], f"Valor numérico inválido: {part}"
    
    sorted_ports = sorted(list(ports))
    
    # Validate against max_ports
    for p in sorted_ports:
        if p < 1 or p > max_ports:
            return False, [], f"El puerto {p} está fuera de rango (1-{max_ports})"
    
    return True, sorted_ports, ""

def validate_vlan_string(vlan_str: str, min_vlan: int = 1, max_vlan: int = 4094) -> Tuple[bool, str, str]:
    """
    Validates a VLAN string (e.g., '10', '10-20', '10,20,30-40').
    Supports spaces and complex formats.
    Returns: (is_valid, cleaned_string, error_msg)
    """
    cleaned = _clean_range_string(vlan_str)
    if cleaned is None:
        return False, "", f"Caracteres inválidos en VLAN: {vlan_str}"
    if not cleaned:
        return False, "", "El campo VLAN está vacío"

    # Validate each part to ensure they are within min/max
    parts = cleaned.split(',')
    for part in parts:
        if not part: continue
        try:
            if '-' in part:
                start_str, end_str = part.split('-', 1)
                start, end = int(start_str), int(end_str)
                if start > end or start < min_vlan or end > max_vlan:
                    return False, "", f"Rango VLAN fuera de límites ({min_vlan}-{max_vlan}): {part}"
            else:
                v = int(part)
                if v < min_vlan or v > max_vlan:
                    return False, "", f"VLAN fuera de límites ({min_vlan}-{max_vlan}): {v}"
        except ValueError:
            return False, "", f"Formato de VLAN inválido: {part}"

    return True, cleaned, ""

def parse_config_blocks(actions_str: str) -> List[Dict[str, Any]]:
    """
    Parses a string of actions separated by '/'.
    Intelligently handles commas within values (ranges).
    Example: 'ports:1,2-4, vlan:10 / hostname:Switch'
    """
    blocks = []
    if not actions_str:
        return blocks
    
    raw_blocks = [b.strip() for b in actions_str.split('/') if b.strip()]
    for rb in raw_blocks:
        block_dict = {}
        # Split by comma but be careful: if a segment doesn't have ':', 
        # it probably belongs to the previous key's value (comma-separated range)
        raw_parts = [p.strip() for p in rb.split(',') if p.strip()]
        
        last_key = None
        for part in raw_parts:
            if ':' in part:
                key, value = part.split(':', 1)
                last_key = key.strip()
                block_dict[last_key] = value.strip()
            else:
                # No colon found. If we have a last_key, append this to its value.
                if last_key:
                    block_dict[last_key] += "," + part.strip()
                else:
                    # No key yet, treat as a flag? (Legacy behavior)
                    block_dict[part.strip()] = True
        
        blocks.append(block_dict)
    
    return blocks
def sanitize_config_value(value: str) -> str:
    """Sanitiza valores de configuración para evitar inyecciones e inestabilidades."""
    if not isinstance(value, str):
        return str(value)
    # Bloquear caracteres de control y redirección: ; & | ' ` $ > < ! \ { } [ ]
    return re.sub(r"[;&|'`$><!\\{}\[\]]", "", value).strip()

def load_profile(profile_id: str, profiles_dir: str) -> Optional[Dict[str, Any]]:
    """Carga un perfil de hardware desde JSON."""
    profile_path = os.path.join(profiles_dir, f"{profile_id}.json")
    if not os.path.exists(profile_path):
        return None
    try:
        with open(profile_path, 'r') as f:
            return json.load(f)
    except Exception:
        return None

def get_secrets(ip: str, secrets_json: str) -> Tuple[Optional[str], Optional[str]]:
    """Obtiene usuario y contraseña para una IP."""
    if not os.path.exists(secrets_json):
        return None, None
    try:
        with open(secrets_json, 'r') as f:
            secrets = json.load(f)
        data = secrets.get(ip, {})
        return data.get("user"), data.get("password")
    except Exception:
        return None, None

def parse_ports(ports_str: str) -> List[int]:
    """Valida y convierte una lista de puertos (ej: '1,2-4') en lista plana."""
    if " " in ports_str:
        raise ValueError("El parámetro de puertos NO debe contener espacios.")
        
    ports = set()
    parts = ports_str.split(',')
    
    for part in parts:
        if not part: continue
        if '-' in part:
            try:
                # Usamos una lógica similar a validate_port_range
                start_str, end_str = part.split('-', 1)
                start, end = int(start_str), int(end_str)
                if start > end:
                    raise ValueError(f"Rango inválido: {start}-{end}")
                ports.update(range(start, end + 1))
            except ValueError:
                raise ValueError(f"Valor numérico inválido en rango: {part}")
        else:
            try:
                ports.add(int(part))
            except ValueError:
                raise ValueError(f"Valor numérico inválido: {part}")
            
    return sorted(list(ports))
