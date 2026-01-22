# app/core/tagging.py

import subprocess
import json
import os
from typing import Dict, Any, Tuple, Optional
from ..utils.global_functions import create_module_config_directory, create_module_log_directory

# Config file in V4 structure
CONFIG_FILE = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "config", "tagging", "tagging.json")
)

# -----------------------------
# Utilidades internas
# -----------------------------

def _load_config() -> dict:
    if not os.path.exists(CONFIG_FILE):
        return {"interfaces": [], "status": 0}
    try:
        with open(CONFIG_FILE, "r") as f:
            data = json.load(f)
            if "status" not in data:
                data["status"] = 0
            return data
    except Exception:
        return {"interfaces": [], "status": 0}


def _save_config(data: dict) -> None:
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    with open(CONFIG_FILE, "w") as f:
        json.dump(data, f, indent=4)


def _update_status(status: int) -> None:
    cfg = _load_config()
    cfg["status"] = status
    _save_config(cfg)


def _bridge_exists() -> bool:
    return os.path.exists("/sys/class/net/br0")


def _run_cmd(cmd: list, ignore_error: bool = False) -> Tuple[bool, str]:
    """Ejecuta un comando y retorna (éxito, mensaje_error)"""
    try:
        result = subprocess.run(
            ["sudo"] + cmd,
            capture_output=True,
            text=True,
            check=not ignore_error
        )
        return True, ""
    except subprocess.CalledProcessError as e:
        error_msg = e.stderr.strip() if e.stderr else str(e)
        return False, error_msg


# -----------------------------
# Acciones públicas (Admin API)
# -----------------------------

def start(params: Dict[str, Any] = None) -> Tuple[bool, str]:
    create_module_config_directory("tagging")
    create_module_log_directory("tagging")
    
    cfg = _load_config()
    interfaces = cfg.get("interfaces", [])
    
    if not interfaces:
        return False, "No hay interfaces configuradas para tagging"
    
    if not _bridge_exists():
        return False, "Bridge br0 no existe. Configure VLANs primero"
    
    # Solo tocar VLAN 1 si hay interfaces físicas
    if interfaces:
        _run_cmd(["/usr/sbin/bridge", "vlan", "del", "dev", "br0", "vid", "1", "pvid", "untagged"], ignore_error=True)
    
    # Acumular errores y resultados
    errors = []
    success_list = []
    
    # Configurar TAG/UNTAG en interfaces físicas
    for iface in interfaces:
        name = iface.get("name")
        vlan_untag = iface.get("vlan_untag")
        vlan_tag = iface.get("vlan_tag")
        
        if not name:
            continue
        
        iface_errors = []
        
        # Agregar interfaz al bridge
        success, error = _run_cmd(["/usr/sbin/ip", "link", "set", name, "master", "br0"], ignore_error=True)
        if not success:
            iface_errors.append(f"agregando al bridge: {error}")
        
        success, error = _run_cmd(["/usr/sbin/ip", "link", "set", name, "up"])
        if not success:
            iface_errors.append(f"habilitando: {error}")
        
        # Eliminar VLAN 1 por defecto en la interfaz
        _run_cmd(["/usr/sbin/bridge", "vlan", "del", "dev", name, "vid", "1", "pvid", "untagged"], ignore_error=True)
        
        # VLAN UNTAG
        if vlan_untag:
            success, error = _run_cmd(["/usr/sbin/bridge", "vlan", "add", "dev", name, "vid", str(vlan_untag), "pvid", "untagged"], ignore_error=True)
            if not success:
                iface_errors.append(f"UNTAG VLAN {vlan_untag}: {error}")
            success, error = _run_cmd(["/usr/sbin/bridge", "vlan", "add", "dev", "br0", "vid", str(vlan_untag), "self"], ignore_error=True)
            if not success:
                iface_errors.append(f"VLAN {vlan_untag} al bridge: {error}")
        
        # VLAN TAG
        if vlan_tag:
            for vid in str(vlan_tag).split(","):
                vid = vid.strip()
                if vid:
                    success, error = _run_cmd(["/usr/sbin/bridge", "vlan", "add", "dev", name, "vid", vid], ignore_error=True)
                    if not success:
                        iface_errors.append(f"TAG VLAN {vid}: {error}")
                    success, error = _run_cmd(["/usr/sbin/bridge", "vlan", "add", "dev", "br0", "vid", vid, "self"], ignore_error=True)
                    if not success:
                        iface_errors.append(f"VLAN {vid} al bridge: {error}")
        
        if iface_errors:
            errors.append(f"  {name}: " + ", ".join(iface_errors))
        else:
            config_info = []
            if vlan_untag:
                config_info.append(f"UNTAG={vlan_untag}")
            if vlan_tag:
                config_info.append(f"TAG={vlan_tag}")
            success_list.append(f"  {name}: " + ", ".join(config_info) if config_info else f"  {name}")
    
    _update_status(1 if len(success_list) > 0 else 0)
    
    result_msg = ""
    
    if success_list:
        result_msg += "Interfaces configuradas correctamente:\n" + "\n".join(success_list)
    
    if errors:
        if result_msg:
            result_msg += "\n\n"
        result_msg += "Errores en interfaces:\n" + "\n".join(errors)
        return True if success_list else False, result_msg
    
    return True, result_msg if result_msg else "Tagging configurado correctamente"


def stop(params: Dict[str, Any] = None) -> Tuple[bool, str]:
    create_module_config_directory("tagging")
    create_module_log_directory("tagging")
    
    cfg = _load_config()
    interfaces = cfg.get("interfaces", [])
    
    # Remover interfaces del bridge y limpiar configuración VLAN
    for iface in interfaces:
        name = iface.get("name")
        if not name:
            continue
        
        # Remover del bridge
        _run_cmd(["/usr/sbin/ip", "link", "set", name, "nomaster"], ignore_error=True)
        
        # Limpiar configuración VLAN
        _run_cmd(["/usr/sbin/bridge", "vlan", "del", "dev", name, "vid", "1-4094"], ignore_error=True)
    
    _update_status(0)
    return True, "Tagging detenido"


def restart(params: Dict[str, Any] = None) -> Tuple[bool, str]:
    ok, msg = stop()
    if not ok:
        return False, msg
    return start()


def status(params: Dict[str, Any] = None) -> Tuple[bool, str]:
    create_module_config_directory("tagging")
    create_module_log_directory("tagging")
    
    cfg = _load_config()
    active = cfg.get("status", 0) == 1
    
    status_msg = "Tagging ACTIVO" if active else "Tagging INACTIVO"
    
    # Mostrar interfaces configuradas
    interfaces_info = "\nINTERFACES CONFIGURADAS:\n"
    interfaces = cfg.get("interfaces", [])
    if interfaces:
        for iface in interfaces:
            interfaces_info += f"  {iface.get('name')}: UNTAG={iface.get('vlan_untag', '')}, TAG={iface.get('vlan_tag', '')}\n"
    else:
        interfaces_info += "  (sin interfaces)\n"
    
    # Mostrar estado del bridge
    interfaces_info += "\nESTADO DEL BRIDGE:\n"
    try:
        result = subprocess.run(
            ["sudo", "bridge", "vlan", "show"],
            capture_output=True,
            text=True,
            check=True
        )
        if result.stdout.strip():
            interfaces_info += result.stdout.rstrip()
        else:
            interfaces_info += "(sin datos)"
    except subprocess.CalledProcessError:
        interfaces_info += "Error obteniendo estado del bridge"
    
    return True, f"{status_msg}{interfaces_info}"


def config(params: Dict[str, Any]) -> Tuple[bool, str]:
    create_module_config_directory("tagging")
    create_module_log_directory("tagging")
    
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
        name = params.get("name")
        if not name:
            return False, "Falta parámetro obligatorio 'name'"
        
        if not isinstance(name, str):
            return False, f"Error: 'name' debe ser una cadena, recibido: {type(name).__name__}"
        
        name = name.strip()
        
        if not name:
            return False, "Error: 'name' no puede estar vacío"
        
        # Validar formato de nombre de interfaz
        import re
        if not re.match(r'^[a-zA-Z0-9._-]+$', name):
            return False, f"Error: formato de nombre de interfaz inválido: '{name}'. Debe ser alfanumérico con guiones, puntos o barras bajas"
        
        # Normalizar campos vacíos
        vlan_untag = params.get("vlan_untag", "")
        vlan_tag = params.get("vlan_tag", "")
        
        # Validar vlan_untag si se proporciona
        if vlan_untag:
            if not isinstance(vlan_untag, (str, int)):
                return False, f"Error: 'vlan_untag' debe ser una cadena o número, recibido: {type(vlan_untag).__name__}"
            
            try:
                untag_id = int(vlan_untag)
                if untag_id < 1 or untag_id > 4094:
                    return False, f"Error: 'vlan_untag' debe estar entre 1 y 4094, recibido: {untag_id}"
                vlan_untag = str(untag_id)
            except (ValueError, TypeError):
                return False, f"Error: 'vlan_untag' debe ser un número válido, recibido: {vlan_untag}"
        
        # Validar vlan_tag si se proporciona
        if vlan_tag:
            if not isinstance(vlan_tag, str):
                return False, f"Error: 'vlan_tag' debe ser una cadena, recibido: {type(vlan_tag).__name__}"
            
            # Puede ser lista separada por comas
            vlan_tag = vlan_tag.strip()
            if vlan_tag:
                tag_list = [t.strip() for t in vlan_tag.split(',')]
                for tag in tag_list:
                    try:
                        tag_id = int(tag)
                        if tag_id < 1 or tag_id > 4094:
                            return False, f"Error: cada VLAN en 'vlan_tag' debe estar entre 1 y 4094, recibido: {tag_id}"
                    except (ValueError, TypeError):
                        return False, f"Error: 'vlan_tag' contiene un valor inválido: {tag}"
        
        # Eliminar si ya existía la interfaz
        cfg["interfaces"] = [i for i in cfg["interfaces"] if i.get("name") != name]
        
        # Agregar nueva
        cfg["interfaces"].append({
            "name": name,
            "vlan_untag": str(vlan_untag) if vlan_untag else "",
            "vlan_tag": vlan_tag
        })
        _save_config(cfg)
        return True, f"Interfaz {name} agregada"
    
    elif action == "remove":
        name = params.get("name")
        if not name:
            return False, "Falta parámetro obligatorio 'name'"
        
        if not isinstance(name, str):
            return False, f"Error: 'name' debe ser una cadena, recibido: {type(name).__name__}"
        
        name = name.strip()
        
        if not name:
            return False, "Error: 'name' no puede estar vacío"
        
        original_count = len(cfg["interfaces"])
        cfg["interfaces"] = [i for i in cfg["interfaces"] if i.get("name") != name]
        if len(cfg["interfaces"]) == original_count:
            return False, f"Interfaz {name} no encontrada"
        
        _save_config(cfg)
        return True, f"Interfaz {name} eliminada"
    
    elif action == "show":
        interfaces = cfg.get("interfaces", [])
        if not interfaces:
            return True, "No hay interfaces configuradas"
        
        result = "Interfaces configuradas:\n"
        for iface in interfaces:
            result += f"  Name: {iface.get('name')}, UNTAG: {iface.get('vlan_untag', '')}, TAG: {iface.get('vlan_tag', '')}\n"
        return True, result.rstrip()
    
    else:
        return False, f"Acción no válida: '{action}'. Use: add, remove, show"


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