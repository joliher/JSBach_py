# app/core/vlans.py

import os
import re
import subprocess
from typing import Dict, Any, Tuple, Optional
from ..utils.global_functions import create_module_config_directory, create_module_log_directory
from ..utils.validators import validate_vlan_id, validate_ip_network
from ..utils.helpers import (
    load_json_config, save_json_config, update_module_status, run_command
)

# Config file in V4 structure
CONFIG_FILE = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "config", "vlans", "vlans.json")
)

# Alias helpers para compatibilidad
_load_config = lambda: load_json_config(CONFIG_FILE, {"vlans": [], "status": 0})
_save_config = lambda data: save_json_config(CONFIG_FILE, data)
_update_status = lambda status: update_module_status(CONFIG_FILE, status)
_run_cmd = lambda cmd, ignore_error=False: run_command(cmd)[0]


def _initialize_default_vlans() -> None:
    """Asegurar que VLANs 1 y 2 existan siempre por defecto."""
    cfg = _load_config()
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
    _save_config(cfg)


def _bridge_exists() -> bool:
    return os.path.exists("/sys/class/net/br0")


# -----------------------------
# Acciones públicas (Admin API)
# -----------------------------

def start(params: Dict[str, Any] = None) -> Tuple[bool, str]:
    create_module_config_directory("vlans")
    create_module_log_directory("vlans")
    _initialize_default_vlans()
    
    cfg = _load_config()
    vlans = cfg.get("vlans", [])
    
    if not vlans:
        return False, "No hay VLANs configuradas"
    
    # Crear br0 si no existe
    if not _bridge_exists():
        if not _run_cmd(["/usr/sbin/ip", "link", "add", "name", "br0", "type", "bridge", "vlan_filtering", "1"], ignore_error=True):
            return False, "Error creando bridge br0"
    
    if not _run_cmd(["/usr/sbin/ip", "link", "set", "br0", "up"]):
        return False, "Error habilitando bridge br0"
    
    # Crear subinterfaces VLAN y asignar IPs
    for vlan in vlans:
        vlan_id = str(vlan.get("id"))
        vlan_ip_interface = vlan.get("ip_interface")
        iface_name = f"br0.{vlan_id}"
        
        if not os.path.exists(f"/sys/class/net/{iface_name}"):
            if not _run_cmd(["/usr/sbin/ip", "link", "add", "link", "br0", "name", iface_name, "type", "vlan", "id", vlan_id], ignore_error=True):
                return False, f"Error creando interfaz VLAN {iface_name}"
        
        if not _run_cmd(["/usr/sbin/ip", "link", "set", iface_name, "up"]):
            return False, f"Error habilitando interfaz VLAN {iface_name}"
        
        # Asignar IP de interfaz directamente
        if vlan_ip_interface:
            if not _run_cmd(["/usr/sbin/ip", "addr", "add", vlan_ip_interface, "dev", iface_name], ignore_error=True):
                return False, f"Error asignando IP {vlan_ip_interface} a {iface_name}"
    
    _update_status(1)
    return True, "VLANs iniciadas"


def stop(params: Dict[str, Any] = None) -> Tuple[bool, str]:
    create_module_config_directory("vlans")
    create_module_log_directory("vlans")
    
    # Cargar configuración para obtener las VLANs
    cfg = _load_config()
    vlans = cfg.get("vlans", [])
    
    # Eliminar subinterfaces VLAN primero
    for vlan in vlans:
        vlan_id = str(vlan.get("id"))
        iface_name = f"br0.{vlan_id}"
        # Intentar eliminar (puede no existir si ya fue eliminada)
        _run_cmd(["/usr/sbin/ip", "link", "set", iface_name, "down"], ignore_error=True)
        _run_cmd(["/usr/sbin/ip", "link", "del", "dev", iface_name], ignore_error=True)
    
    # Luego eliminar bridge
    if _bridge_exists():
        if not _run_cmd(["/usr/sbin/ip", "link", "set", "br0", "down"], ignore_error=True):
            return False, "Error deteniendo bridge br0"
        if not _run_cmd(["/usr/sbin/ip", "link", "del", "dev", "br0"], ignore_error=True):
            return False, "Error eliminando bridge br0"
    
    _update_status(0)
    return True, "VLANs detenidas"


def restart(params: Dict[str, Any] = None) -> Tuple[bool, str]:
    ok, msg = stop()
    if not ok:
        return False, msg
    return start()


def status(params: Dict[str, Any] = None) -> Tuple[bool, str]:
    create_module_config_directory("vlans")
    create_module_log_directory("vlans")
    _initialize_default_vlans()
    
    cfg = _load_config()
    vlans = cfg.get("vlans", [])
    
    # Verificar si el bridge br0 existe y está UP
    br0_exists = _bridge_exists()
    br0_is_up = False
    
    if br0_exists:
        try:
            result = subprocess.run(
                ["sudo", "/usr/sbin/ip", "a", "show", "br0"],
                capture_output=True,
                text=True,
                check=True,
                timeout=5
            )
            br0_is_up = "state UP" in result.stdout
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass
    
    status_lines = ["Estado de VLANs:", "=" * 50]
    
    if not br0_exists:
        status_lines.append("🔴 Bridge br0: NO EXISTE")
        status_lines.append("\n⚠️ Las VLANs requieren que el bridge br0 esté creado")
        return True, "\n".join(status_lines)
    
    br0_status = "🟢 UP" if br0_is_up else "🔴 DOWN"
    status_lines.append(f"Bridge br0: {br0_status}")
    
    # Verificar cada VLAN configurada
    status_lines.append(f"\nVLANs configuradas: {len(vlans)}")
    status_lines.append("-" * 50)
    
    if vlans:
        for vlan in vlans:
            vlan_id = vlan.get('id')
            vlan_name = vlan.get('name', 'Sin nombre')
            ip_int = vlan.get('ip_interface', 'N/A')
            ip_net = vlan.get('ip_network', 'N/A')
            
            # Verificar si la subinterfaz br0.X existe y está UP
            subif_name = f"br0.{vlan_id}"
            try:
                result = subprocess.run(
                    ["sudo", "/usr/sbin/ip", "a", "show", subif_name],
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=5
                )
                is_up = "state UP" in result.stdout
                has_ip = f"inet {ip_int.split('/')[0]}" in result.stdout if '/' in ip_int else False
                subif_status = "🟢 UP" if is_up else "🔴 DOWN"
                ip_status = " ✅" if has_ip else " ⚠️ Sin IP"
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                subif_status = "❌ NO EXISTE"
                ip_status = ""
            
            status_lines.append(f"\nVLAN {vlan_id} ({vlan_name}):")
            status_lines.append(f"  Interfaz: {subif_name} [{subif_status}]{ip_status}")
            status_lines.append(f"  IP: {ip_int}")
            status_lines.append(f"  Red: {ip_net}")
    else:
        status_lines.append("\n(Sin VLANs configuradas)")
    
    return True, "\n".join(status_lines)
    
    return True, f"{status_msg}{vlans_info}"


def config(params: Dict[str, Any]) -> Tuple[bool, str]:
    create_module_config_directory("vlans")
    create_module_log_directory("vlans")
    _initialize_default_vlans()
    
    # Validar parámetros
    if not params:
        return False, "Error: No se proporcionaron parámetros"
    
    if not isinstance(params, dict):
        return False, "Error: Los parámetros deben ser un diccionario"
    
    action = params.get("action")
    if not action:
        return False, "Falta parámetro 'action'"
    
    if not isinstance(action, str):
        return False, f"Error: 'action' debe ser una cadena, recibido: {type(action).__name__}"
    
    action = action.strip().lower()
    
    if not action:
        return False, "Error: 'action' no puede estar vacío"
    
    cfg = _load_config()
    
    if action == "add":
        required = ["id", "name"]
        for r in required:
            if r not in params:
                return False, f"Falta parámetro obligatorio '{r}'"
        
        # Validar id
        try:
            vlan_id = int(params["id"])
        except (ValueError, TypeError):
            return False, f"Error: 'id' debe ser un número entero, recibido: {params['id']}"
        
        if vlan_id < 1 or vlan_id > 4094:
            return False, f"Error: 'id' debe estar entre 1 y 4094, recibido: {vlan_id}"
        
        # Validar name
        if not isinstance(params["name"], str):
            return False, f"Error: 'name' debe ser una cadena, recibido: {type(params['name']).__name__}"
        
        name = params["name"].strip()
        
        if not name:
            return False, "Error: 'name' no puede estar vacío"
        
        ip_interface = params.get("ip_interface", "").strip()
        ip_network = params.get("ip_network", "").strip()
        
        # Validar IP de interfaz si se proporciona
        if ip_interface:
            if not isinstance(ip_interface, str):
                return False, f"Error: 'ip_interface' debe ser una cadena, recibido: {type(ip_interface).__name__}"
            
            if '/' not in ip_interface:
                return False, "Error: la IP de interfaz debe incluir la máscara (ejemplo: 192.168.1.1/24)"
            
            try:
                import ipaddress
                ip_int_obj = ipaddress.IPv4Network(ip_interface, strict=False)
                
                # Validar que el último octeto no sea 0 ni 255
                ip_parts = ip_interface.split('/')[0].split('.')
                last_octet = int(ip_parts[3])
                
                if last_octet == 0 or last_octet == 255:
                    return False, "Error: la IP de interfaz no puede terminar en 0 o 255"
                
            except ValueError as e:
                return False, f"Error: formato de IP de interfaz inválido: {str(e)}"
        
        # Validar IP de red si se proporciona
        if ip_network:
            if not isinstance(ip_network, str):
                return False, f"Error: 'ip_network' debe ser una cadena, recibido: {type(ip_network).__name__}"
            
            if '/' not in ip_network:
                return False, "Error: la IP de red debe incluir la máscara (ejemplo: 192.168.1.0/24)"
            
            try:
                import ipaddress
                network = ipaddress.IPv4Network(ip_network, strict=False)
                
                # Validar que sea una dirección de red (último octeto 0)
                ip_parts = ip_network.split('/')[0].split('.')
                last_octet = int(ip_parts[3])
                
                if last_octet != 0:
                    return False, f"Error: la IP de red debe tener último octeto 0. Use {network.network_address}/{network.prefixlen}"
            except ValueError as e:
                return False, f"Error: formato de IP de red inválido: {str(e)}"
        
        # Validar que la IP de interfaz esté dentro de la red especificada
        if ip_interface and ip_network:
            try:
                import ipaddress
                ip_int_addr = ipaddress.IPv4Address(ip_interface.split('/')[0])
                network_obj = ipaddress.IPv4Network(ip_network, strict=False)
                
                if ip_int_addr not in network_obj:
                    return False, f"Error: la IP de interfaz {ip_interface.split('/')[0]} no está dentro de la red {ip_network}"
                
                # Validar que ambas tengan la misma máscara
                ip_int_mask = int(ip_interface.split('/')[1])
                ip_net_mask = int(ip_network.split('/')[1])
                
                if ip_int_mask != ip_net_mask:
                    return False, f"Error: la máscara de la IP de interfaz (/{ip_int_mask}) debe coincidir con la máscara de la red (/{ip_net_mask})"
                
            except (ValueError, IndexError) as e:
                return False, f"Error validando compatibilidad de IPs: {str(e)}"
        
        # Eliminar si ya existe (solo si no es VLAN protegida)
        cfg["vlans"] = [v for v in cfg["vlans"] if v.get("id") != vlan_id]
        # Agregar nueva
        cfg["vlans"].append({
            "id": vlan_id,
            "name": name,
            "ip_interface": ip_interface,
            "ip_network": ip_network
        })
        _save_config(cfg)
        return True, f"VLAN {vlan_id} agregada"
    
    elif action == "remove":
        vlan_id = params.get("id")
        if not vlan_id:
            return False, "Falta parámetro 'id'"
        
        # Proteger VLANs 1 y 2
        if int(vlan_id) in [1, 2]:
            return False, f"VLAN {vlan_id} es protegida y no puede ser eliminada"
        
        original_count = len(cfg["vlans"])
        cfg["vlans"] = [v for v in cfg["vlans"] if str(v.get("id")) != str(vlan_id)]
        if len(cfg["vlans"]) == original_count:
            return False, f"VLAN {vlan_id} no encontrada"
        
        _save_config(cfg)
        return True, f"VLAN {vlan_id} eliminada"
    
    elif action == "show":
        vlans = cfg.get("vlans", [])
        if not vlans:
            return True, "No hay VLANs configuradas"
        
        result = "VLANs configuradas:\n"
        for vlan in vlans:
            ip_int = vlan.get('ip_interface', 'N/A')
            ip_net = vlan.get('ip_network', 'N/A')
            result += f"  ID: {vlan.get('id')}, Name: {vlan.get('name')}, IP Interfaz: {ip_int}, IP Red: {ip_net}\n"
        return True, result.rstrip()
    
    else:
        return False, "Acción no válida. Use: add, remove, show"


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