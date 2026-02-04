# app/core/helpers/helper_vlans.py
"""Helper functions para el módulo VLANs."""

import os
from typing import Dict, Any
from ...utils.helpers import load_json_config, save_json_config, run_command


def initialize_default_vlans(config_file: str) -> None:
    """Asegurar que VLANs 1 y 2 existan siempre por defecto.
    
    Args:
        config_file: Ruta al archivo vlans.json
    """
    cfg = load_json_config(config_file, {"vlans": [], "status": 0})
    vlans = cfg.get("vlans", [])
    
    # Verificar si VLAN 1 existe
    vlan1_exists = any(v.get("id") == 1 for v in vlans)
    if not vlan1_exists:
        vlans.append({
            "id": 1,
            "name": "Admin",
            "ip_interface": "192.168.1.1/24",
            "ip_network": "192.168.1.0/24"
        })
    
    # Verificar si VLAN 2 existe
    vlan2_exists = any(v.get("id") == 2 for v in vlans)
    if not vlan2_exists:
        vlans.append({
            "id": 2,
            "name": "DMZ",
            "ip_interface": "192.168.2.1/24",
            "ip_network": "192.168.2.0/24"
        })
    
    cfg["vlans"] = vlans
    save_json_config(config_file, cfg)


def bridge_exists() -> bool:
    """Verificar si el bridge br0 existe.
    
    Returns:
        True si existe, False en caso contrario
    """
    return os.path.exists("/sys/class/net/br0")
