# app/core/firewall.py - Versión simplificada

import subprocess
import json
import os
import logging
from typing import Dict, Any, Tuple, List

# Configurar logging
logger = logging.getLogger(__name__)

# Directorios
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
CONFIG_DIR = os.path.join(BASE_DIR, "config", "firewall")
VLANS_CONFIG_FILE = os.path.join(BASE_DIR, "config", "vlans", "vlans.json")
FIREWALL_CONFIG_FILE = os.path.join(CONFIG_DIR, "firewall.json")

# -----------------------------
# Utilidades
# -----------------------------

def _ensure_dirs():
    """Crear directorios necesarios."""
    os.makedirs(CONFIG_DIR, exist_ok=True)
    os.makedirs(os.path.join(BASE_DIR, "logs", "firewall"), exist_ok=True)


def _load_vlans_config() -> dict:
    """Cargar configuración de VLANs."""
    if not os.path.exists(VLANS_CONFIG_FILE):
        return {"vlans": [], "status": 0}
    try:
        with open(VLANS_CONFIG_FILE, "r") as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Error cargando VLANs config: {e}")
        return {"vlans": [], "status": 0}


def _load_firewall_config() -> dict:
    """Cargar configuración del firewall."""
    if not os.path.exists(FIREWALL_CONFIG_FILE):
        return {"vlans": {}, "status": 0}
    try:
        with open(FIREWALL_CONFIG_FILE, "r") as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Error cargando firewall config: {e}")
        return {"vlans": {}, "status": 0}


def _save_firewall_config(data: dict) -> None:
    """Guardar configuración del firewall."""
    _ensure_dirs()
    try:
        with open(FIREWALL_CONFIG_FILE, "w") as f:
            json.dump(data, f, indent=4)
        logger.info("Configuración guardada correctamente")
    except Exception as e:
        logger.error(f"Error guardando configuración: {e}")


def _run_command(cmd: list) -> Tuple[bool, str]:
    """Ejecutar comando con timeout y logging."""
    cmd_str = " ".join(cmd)
    logger.info(f"Ejecutando: {cmd_str}")
    
    try:
        # Usar sudo -n para evitar prompt de contraseña
        full_cmd = ["sudo", "-n"] + cmd
        result = subprocess.run(
            full_cmd,
            capture_output=True,
            text=True,
            timeout=5,
            check=False
        )
        
        if result.returncode == 0:
            logger.info(f"Comando exitoso: {cmd_str}")
            return True, result.stdout
        else:
            error_msg = result.stderr.strip() or "Comando falló sin mensaje de error"
            logger.warning(f"Comando falló ({result.returncode}): {error_msg}")
            return False, error_msg
            
    except subprocess.TimeoutExpired:
        error_msg = f"Timeout ejecutando: {cmd_str}"
        logger.error(error_msg)
        return False, error_msg
    except Exception as e:
        error_msg = f"Error inesperado: {str(e)}"
        logger.error(error_msg)
        return False, error_msg


def _apply_whitelist(vlan_id: int, whitelist: List[str]) -> Tuple[bool, str]:
    """Aplicar whitelist a una cadena VLAN (solo permite destinos especificados)."""
    chain_name = f"VLAN_{vlan_id}"
    
    logger.info(f"Aplicando whitelist a VLAN {vlan_id} con {len(whitelist)} reglas")
    
    # Limpiar reglas actuales de la cadena
    _run_command(["/usr/sbin/iptables", "-F", chain_name])
    
    # Añadir reglas de whitelist
    for rule in whitelist:
        rule = rule.strip()
        if not rule:
            continue
        
        # Detectar protocolo (formato: regla/tcp o regla/udp)
        protocol = None
        if rule.endswith('/tcp'):
            protocol = 'tcp'
            rule = rule[:-4]
        elif rule.endswith('/udp'):
            protocol = 'udp'
            rule = rule[:-4]
        
        # Parsear regla
        if rule.startswith(':'):
            # Formato: ":puerto" o ":puerto/protocolo" - cualquier IP hacia un puerto
            port = rule[1:]
            if protocol:
                # Puerto específico con protocolo
                cmd = ["/usr/sbin/iptables", "-A", chain_name, "-p", protocol, "--dport", port, "-j", "ACCEPT"]
            else:
                # Puerto con ambos protocolos (tcp y udp)
                _run_command(["/usr/sbin/iptables", "-A", chain_name, "-p", "tcp", "--dport", port, "-j", "ACCEPT"])
                cmd = ["/usr/sbin/iptables", "-A", chain_name, "-p", "udp", "--dport", port, "-j", "ACCEPT"]
            success, error = _run_command(cmd)
            if not success:
                logger.warning(f"Error aplicando regla {rule}: {error}")
                
        elif ':' in rule:
            # Formato: "ip:puerto" con o sin protocolo
            ip, port = rule.split(':', 1)
            if protocol:
                # IP:puerto con protocolo específico
                cmd = ["/usr/sbin/iptables", "-A", chain_name, "-d", ip, "-p", protocol, "--dport", port, "-j", "ACCEPT"]
            else:
                # IP:puerto con ambos protocolos
                _run_command(["/usr/sbin/iptables", "-A", chain_name, "-d", ip, "-p", "tcp", "--dport", port, "-j", "ACCEPT"])
                cmd = ["/usr/sbin/iptables", "-A", chain_name, "-d", ip, "-p", "udp", "--dport", port, "-j", "ACCEPT"]
            success, error = _run_command(cmd)
            if not success:
                logger.warning(f"Error aplicando regla {rule}: {error}")
                
        else:
            # Formato: solo "ip" con o sin protocolo
            if protocol:
                cmd = ["/usr/sbin/iptables", "-A", chain_name, "-d", rule, "-p", protocol, "-j", "ACCEPT"]
            else:
                cmd = ["/usr/sbin/iptables", "-A", chain_name, "-d", rule, "-j", "ACCEPT"]
            success, error = _run_command(cmd)
            if not success:
                logger.warning(f"Error aplicando regla {rule}: {error}")
    
    # Regla por defecto: DROP todo lo demás
    success, error = _run_command(["/usr/sbin/iptables", "-A", chain_name, "-j", "DROP"])
    if not success:
        logger.error(f"Error añadiendo regla DROP: {error}")
        return False, error
    
    logger.info(f"Whitelist aplicada exitosamente a VLAN {vlan_id}")
    return True, "Whitelist aplicada correctamente"


def _remove_whitelist(vlan_id: int) -> Tuple[bool, str]:
    """Remover whitelist de una VLAN (permite todo el tráfico)."""
    chain_name = f"VLAN_{vlan_id}"
    
    logger.info(f"Removiendo whitelist de VLAN {vlan_id}")
    
    # Limpiar todas las reglas de la cadena
    _run_command(["/usr/sbin/iptables", "-F", chain_name])
    
    # Volver a ACCEPT por defecto
    _run_command(["/usr/sbin/iptables", "-A", chain_name, "-j", "ACCEPT"])
    
    logger.info(f"Whitelist removida, tráfico ACCEPT por defecto")
    return True, "Whitelist deshabilitada"


# -----------------------------
# Funciones principales
# -----------------------------

def start(params: Dict[str, Any] = None) -> Tuple[bool, str]:
    """Iniciar firewall - habilitar cadenas de iptables por VLAN."""
    logger.info("=== INICIO: firewall start ===")
    _ensure_dirs()
    
    vlans_cfg = _load_vlans_config()
    vlans = vlans_cfg.get("vlans", [])
    
    if not vlans:
        msg = "No hay VLANs configuradas. Configure VLANs primero."
        logger.warning(msg)
        return False, msg
    
    fw_cfg = _load_firewall_config()
    if "vlans" not in fw_cfg:
        fw_cfg["vlans"] = {}
    
    results = []
    errors = []
    
    for vlan in vlans:
        vlan_id = vlan.get("id")
        vlan_name = vlan.get("name", "")
        vlan_ip_network = vlan.get("ip_network", "")
        
        logger.info(f"Procesando VLAN {vlan_id} ({vlan_name})")
        
        if not vlan_ip_network:
            errors.append(f"VLAN {vlan_id}: Sin IP de red configurada")
            continue
        
        # Usar la dirección de red completa con máscara para las reglas
        network_address = vlan_ip_network  # Ya viene como 192.168.x.0/24 del config
        
        # Crear cadena personalizada para esta VLAN
        chain_name = f"VLAN_{vlan_id}"
        
        # Crear nueva cadena
        success, output = _run_command(["/usr/sbin/iptables", "-N", chain_name])
        if not success and "already exists" not in output.lower():
            errors.append(f"VLAN {vlan_id}: Error creando cadena")
            continue
        
        # Limpiar reglas existentes de la cadena
        _run_command(["/usr/sbin/iptables", "-F", chain_name])
        
        # Verificar si hay configuración previa con whitelist
        vlan_cfg = fw_cfg.get("vlans", {}).get(str(vlan_id), {})
        whitelist_enabled = vlan_cfg.get("whitelist_enabled", False)
        whitelist = vlan_cfg.get("whitelist", [])
        
        # Aplicar reglas según configuración
        if whitelist_enabled and whitelist:
            # Aplicar whitelist
            logger.info(f"VLAN {vlan_id}: Aplicando whitelist con {len(whitelist)} reglas")
            success, msg = _apply_whitelist(vlan_id, whitelist)
            if not success:
                errors.append(f"VLAN {vlan_id}: Error aplicando whitelist - {msg}")
        else:
            # Regla por defecto: ACCEPT (sin firewall activo)
            _run_command(["/usr/sbin/iptables", "-A", chain_name, "-j", "ACCEPT"])
        
        # Vincular cadena a FORWARD: tráfico desde esta red salta a la cadena VLAN
        # Primero verificar si la regla ya existe
        success, output = _run_command([
            "iptables", "-C", "FORWARD", "-s", network_address, "-j", chain_name
        ])
        
        if not success:  # La regla no existe, agregarla
            success, output = _run_command([
                "iptables", "-A", "FORWARD", "-s", network_address, "-j", chain_name
            ])
            if not success:
                errors.append(f"VLAN {vlan_id}: Error vinculando a FORWARD")
                logger.error(f"Error vinculando VLAN {vlan_id} a FORWARD: {output}")
                continue
            logger.info(f"VLAN {vlan_id}: Vinculada a FORWARD desde {network_address}")
        else:
            logger.info(f"VLAN {vlan_id}: Ya estaba vinculada a FORWARD")
        
        # Actualizar configuración (preservar whitelist si existe)
        if str(vlan_id) not in fw_cfg["vlans"]:
            fw_cfg["vlans"][str(vlan_id)] = {
                "name": vlan_name,
                "enabled": True,
                "whitelist_enabled": False,
                "whitelist": [],
                "ip": network_address,
                "isolated": False
            }
        else:
            # Preservar configuración existente, solo actualizar campos básicos
            fw_cfg["vlans"][str(vlan_id)]["name"] = vlan_name
            fw_cfg["vlans"][str(vlan_id)]["enabled"] = True
            fw_cfg["vlans"][str(vlan_id)]["ip"] = network_address
            # Resetear isolated al iniciar (excepto VLAN 1 que se aislará después)
            if vlan_id != 1:
                fw_cfg["vlans"][str(vlan_id)]["isolated"] = False
        
        results.append(f"VLAN {vlan_id} ({vlan_name}): Cadena creada y vinculada")
    
    # Guardar configuración inicial
    fw_cfg["status"] = 1
    _save_firewall_config(fw_cfg)
    
    # Auto-aislar VLAN 1 después de iniciar el firewall
    if "1" in fw_cfg["vlans"]:
        logger.info("Auto-aislando VLAN 1...")
        vlan1_ip = fw_cfg["vlans"]["1"].get("ip", "")
        
        if vlan1_ip:
            # Calcular IP/máscara
            if '/' not in vlan1_ip:
                ip_mask = f"{vlan1_ip}/24"
            else:
                ip_mask = vlan1_ip
            
            # Verificar si las reglas ya existen antes de crearlas
            check_forward = _run_command([
                "iptables", "-C", "FORWARD", "-d", ip_mask, "-m", "conntrack", 
                "--ctstate", "NEW", "-j", "DROP"
            ])[0]
            
            check_input = _run_command([
                "iptables", "-C", "INPUT", "-d", ip_mask, "-m", "conntrack", 
                "--ctstate", "NEW", "-j", "DROP"
            ])[0]
            
            # Solo crear las reglas si no existen
            if not check_forward:
                success_forward = _run_command([
                    "iptables", "-I", "FORWARD", "1", "-d", ip_mask, "-m", "conntrack", 
                    "--ctstate", "NEW", "-j", "DROP"
                ])[0]
            else:
                success_forward = True
                logger.info("Regla FORWARD para VLAN 1 ya existe, saltando...")
            
            if not check_input:
                success_input = _run_command([
                    "iptables", "-I", "INPUT", "1", "-d", ip_mask, "-m", "conntrack", 
                    "--ctstate", "NEW", "-j", "DROP"
                ])[0]
            else:
                success_input = True
                logger.info("Regla INPUT para VLAN 1 ya existe, saltando...")
            
            if success_forward and success_input:
                # Marcar como aislada en la configuración
                fw_cfg["vlans"]["1"]["isolated"] = True
                _save_firewall_config(fw_cfg)
                results.append("VLAN 1: Auto-aislada (tráfico entrante bloqueado)")
                logger.info("VLAN 1 aislada correctamente")
            else:
                errors.append("VLAN 1: Error al aplicar reglas de aislamiento")
                logger.error("Error aislando VLAN 1")
    
    if not results:
        msg = "No se pudo habilitar ninguna VLAN\n" + "\n".join(errors)
        logger.error(msg)
        return False, msg
    
    msg = "Firewall iniciado:\n" + "\n".join(results)
    if errors:
        msg += "\n\nErrores:\n" + "\n".join(errors)
    
    logger.info("=== FIN: firewall start ===")
    return True, msg


def stop(params: Dict[str, Any] = None) -> Tuple[bool, str]:
    """Detener firewall - eliminar cadenas de iptables."""
    logger.info("=== INICIO: firewall stop ===")
    _ensure_dirs()
    
    fw_cfg = _load_firewall_config()
    vlans = fw_cfg.get("vlans", {})
    
    if not vlans:
        msg = "No hay VLANs configuradas en el firewall"
        logger.warning(msg)
        return True, msg
    
    results = []
    
    # Primero, eliminar todas las reglas de aislamiento
    for vlan_id, vlan_data in vlans.items():
        vlan_ip = vlan_data.get("ip", "")
        isolated = vlan_data.get("isolated", False)
        
        if isolated and vlan_ip:
            logger.info(f"Desaislando VLAN {vlan_id}...")
            
            # Calcular IP/máscara
            if '/' not in vlan_ip:
                ip_mask = f"{vlan_ip}/24"
            else:
                ip_mask = vlan_ip
            
            # VLAN 1 usa -d (destination), otras usan -s (source)
            if vlan_id == "1":
                # Eliminar reglas con -d para VLAN 1
                _run_command([
                    "iptables", "-D", "FORWARD", "-d", ip_mask, "-m", "conntrack", 
                    "--ctstate", "NEW", "-j", "DROP"
                ])
                _run_command([
                    "iptables", "-D", "INPUT", "-d", ip_mask, "-m", "conntrack", 
                    "--ctstate", "NEW", "-j", "DROP"
                ])
            else:
                # Eliminar reglas con -s para otras VLANs
                _run_command([
                    "iptables", "-D", "FORWARD", "-s", ip_mask, "-m", "conntrack", 
                    "--ctstate", "NEW", "-j", "DROP"
                ])
                _run_command([
                    "iptables", "-D", "INPUT", "-s", ip_mask, "-m", "conntrack", 
                    "--ctstate", "NEW", "-j", "DROP"
                ])
            
            logger.info(f"VLAN {vlan_id} desaislada")
        
        # Marcar TODAS las VLANs como no aisladas al detener el firewall
        fw_cfg["vlans"][vlan_id]["isolated"] = False
    
    # Luego, eliminar las cadenas del firewall
    for vlan_id, vlan_data in vlans.items():
        chain_name = f"VLAN_{vlan_id}"
        vlan_name = vlan_data.get("name", "")
        vlan_ip_network = vlan_data.get("ip", "")
        
        logger.info(f"Eliminando cadena para VLAN {vlan_id}")
        
        # Desvincular de FORWARD: eliminar todas las referencias a esta cadena
        if vlan_ip_network:
            logger.info(f"Desvinculando VLAN {vlan_id} de FORWARD (IP: {vlan_ip_network})")
            # Intentar eliminar la regla varias veces por si hay duplicados
            for attempt in range(5):
                success, output = _run_command([
                    "iptables", "-D", "FORWARD", "-s", vlan_ip_network, "-j", chain_name
                ])
                if not success:
                    break  # No hay más reglas que eliminar
                logger.info(f"Regla FORWARD eliminada (intento {attempt + 1})")
        
        # Limpiar reglas de la cadena
        _run_command(["/usr/sbin/iptables", "-F", chain_name])
        
        # Eliminar cadena
        success, output = _run_command(["/usr/sbin/iptables", "-X", chain_name])
        
        # Desactivar whitelist si estaba habilitada
        if fw_cfg["vlans"][vlan_id].get("whitelist_enabled", False):
            fw_cfg["vlans"][vlan_id]["whitelist_enabled"] = False
            logger.info(f"Whitelist desactivada para VLAN {vlan_id}")
        
        fw_cfg["vlans"][vlan_id]["enabled"] = False
        results.append(f"VLAN {vlan_id} ({vlan_name}): Cadena eliminada y desvinculada")
    
    fw_cfg["status"] = 0
    _save_firewall_config(fw_cfg)
    
    msg = "Firewall detenido:\n" + "\n".join(results)
    logger.info("=== FIN: firewall stop ===")
    return True, msg


def restart(params: Dict[str, Any] = None) -> Tuple[bool, str]:
    """Reiniciar firewall."""
    logger.info("=== INICIO: firewall restart ===")
    
    # Detener
    stop_success, stop_msg = stop(params)
    
    # Iniciar
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
        chain_name = f"VLAN_{vlan_id}"
        vlan_name = vlan_data.get("name", "")
        vlan_ip_network = vlan_data.get("ip", "")
        enabled = vlan_data.get("enabled", False)
        whitelist_enabled = vlan_data.get("whitelist_enabled", False)
        
        status_str = "ACTIVA" if enabled else "INACTIVA"
        lines.append(f"\nVLAN {vlan_id} ({vlan_name}): {status_str}")
        if vlan_ip_network:
            lines.append(f"  IP Red: {vlan_ip_network}")
        
        # Verificar si está vinculada a FORWARD
        if vlan_ip_network:
            success, output = _run_command([
                "iptables", "-C", "FORWARD", "-s", vlan_ip_network, "-j", chain_name
            ])
            if success:
                lines.append(f"  Vinculación: ACTIVA en FORWARD")
            else:
                lines.append(f"  Vinculación: NO vinculada a FORWARD")
        
        if whitelist_enabled:
            whitelist = vlan_data.get("whitelist", [])
            lines.append(f"  Whitelist: HABILITADA ({len(whitelist)} reglas)")
        else:
            lines.append(f"  Whitelist: DESHABILITADA")
        
        # Obtener reglas actuales de iptables
        success, output = _run_command(["/usr/sbin/iptables", "-L", chain_name, "-n", "-v"])
        if success and output:
            lines.append(f"  Reglas activas:")
            for line in output.split('\n')[2:5]:  # Primeras 3 reglas
                if line.strip():
                    lines.append(f"    {line.strip()}")
    
    msg = "\n".join(lines)
    logger.info("=== FIN: firewall status ===")
    return True, msg


def config(params: Dict[str, Any] = None) -> Tuple[bool, str]:
    """Configurar firewall (placeholder para la interfaz web)."""
    logger.info("Config llamado desde interfaz web")
    return True, "Use la interfaz web para configurar el firewall"


def enable_whitelist(params: Dict[str, Any] = None) -> Tuple[bool, str]:
    """Habilitar whitelist en una VLAN específica."""
    logger.info("=== INICIO: enable_whitelist ===")
    
    # Validar parámetros
    if not params:
        return False, "Error: No se proporcionaron parámetros"
    
    if not isinstance(params, dict):
        return False, "Error: Los parámetros deben ser un diccionario"
    
    if "vlan_id" not in params:
        return False, "Error: vlan_id requerido"
    
    # Validar vlan_id
    try:
        vlan_id = int(params["vlan_id"])
    except (ValueError, TypeError):
        return False, f"Error: vlan_id debe ser un número entero, recibido: {params['vlan_id']}"
    
    if vlan_id < 1 or vlan_id > 4094:
        return False, f"Error: vlan_id debe estar entre 1 y 4094, recibido: {vlan_id}"
    
    # VLANs 1 y 2 no permiten whitelist
    if vlan_id in (1, 2):
        return False, f"Error: VLAN {vlan_id} no permite configuración de whitelist"
    
    # Validar whitelist
    whitelist = params.get("whitelist", [])
    
    if isinstance(whitelist, str):
        whitelist = [whitelist] if whitelist else []
    elif not isinstance(whitelist, list):
        return False, f"Error: whitelist debe ser una lista o cadena, recibido: {type(whitelist).__name__}"
    
    # Validar cada elemento de la whitelist
    for i, rule in enumerate(whitelist):
        if not isinstance(rule, str):
            return False, f"Error: elemento {i} de whitelist debe ser una cadena, recibido: {type(rule).__name__}"
        if not rule.strip():
            return False, f"Error: elemento {i} de whitelist no puede estar vacío"
    
    fw_cfg = _load_firewall_config()
    
    if str(vlan_id) not in fw_cfg.get("vlans", {}):
        return False, f"VLAN {vlan_id} no encontrada en firewall. Ejecute START primero."
    
    # Guardar configuración
    fw_cfg["vlans"][str(vlan_id)]["whitelist"] = whitelist
    fw_cfg["vlans"][str(vlan_id)]["whitelist_enabled"] = True
    _save_firewall_config(fw_cfg)
    
    # Aplicar whitelist
    success, msg = _apply_whitelist(vlan_id, whitelist)
    
    logger.info(f"=== FIN: enable_whitelist - Success: {success} ===")
    return success, f"Whitelist habilitada en VLAN {vlan_id}\n{msg}"


def disable_whitelist(params: Dict[str, Any] = None) -> Tuple[bool, str]:
    """Deshabilitar whitelist en una VLAN específica."""
    logger.info("=== INICIO: disable_whitelist ===")
    
    # Validar parámetros
    if not params:
        return False, "Error: No se proporcionaron parámetros"
    
    if not isinstance(params, dict):
        return False, "Error: Los parámetros deben ser un diccionario"
    
    if "vlan_id" not in params:
        return False, "Error: vlan_id requerido"
    
    # Validar vlan_id
    try:
        vlan_id = int(params["vlan_id"])
    except (ValueError, TypeError):
        return False, f"Error: vlan_id debe ser un número entero, recibido: {params['vlan_id']}"
    
    if vlan_id < 1 or vlan_id > 4094:
        return False, f"Error: vlan_id debe estar entre 1 y 4094, recibido: {vlan_id}"
    
    # VLANs 1 y 2 no permiten whitelist
    if vlan_id in (1, 2):
        return False, f"Error: VLAN {vlan_id} no permite configuración de whitelist"
    
    fw_cfg = _load_firewall_config()
    
    if str(vlan_id) not in fw_cfg.get("vlans", {}):
        return False, f"VLAN {vlan_id} no encontrada en firewall"
    
    # Actualizar configuración
    fw_cfg["vlans"][str(vlan_id)]["whitelist_enabled"] = False
    _save_firewall_config(fw_cfg)
    
    # Remover whitelist (volver a ACCEPT)
    success, msg = _remove_whitelist(vlan_id)
    
    logger.info(f"=== FIN: disable_whitelist - Success: {success} ===")
    return success, f"Whitelist deshabilitada en VLAN {vlan_id}\n{msg}"


def add_rule(params: Dict[str, Any] = None) -> Tuple[bool, str]:
    """Agregar una regla a la whitelist de una VLAN."""
    logger.info("=== INICIO: add_rule ===")
    
    # Validar parámetros
    if not params:
        return False, "Error: No se proporcionaron parámetros"
    
    if not isinstance(params, dict):
        return False, "Error: Los parámetros deben ser un diccionario"
    
    if "vlan_id" not in params:
        return False, "Error: vlan_id requerido"
    
    if "rule" not in params:
        return False, "Error: rule requerido"
    
    # Validar vlan_id
    try:
        vlan_id = int(params["vlan_id"])
    except (ValueError, TypeError):
        return False, f"Error: vlan_id debe ser un número entero, recibido: {params['vlan_id']}"
    
    if vlan_id < 1 or vlan_id > 4094:
        return False, f"Error: vlan_id debe estar entre 1 y 4094, recibido: {vlan_id}"
    
    # VLANs 1 y 2 no permiten whitelist
    if vlan_id in (1, 2):
        return False, f"Error: VLAN {vlan_id} no permite configuración de whitelist"
    
    # Validar rule
    if not isinstance(params["rule"], str):
        return False, f"Error: rule debe ser una cadena, recibido: {type(params['rule']).__name__}"
    
    new_rule = params["rule"].strip()
    
    if not new_rule:
        return False, "Error: regla vacía"
    
    fw_cfg = _load_firewall_config()
    
    if str(vlan_id) not in fw_cfg.get("vlans", {}):
        return False, f"VLAN {vlan_id} no encontrada en firewall"
    
    # Agregar regla a la configuración
    whitelist = fw_cfg["vlans"][str(vlan_id)].get("whitelist", [])
    
    if new_rule in whitelist:
        return False, f"La regla '{new_rule}' ya existe en la whitelist"
    
    whitelist.append(new_rule)
    fw_cfg["vlans"][str(vlan_id)]["whitelist"] = whitelist
    _save_firewall_config(fw_cfg)
    
    # Si la whitelist está habilitada, reaplicar
    if fw_cfg["vlans"][str(vlan_id)].get("whitelist_enabled", False):
        success, msg = _apply_whitelist(vlan_id, whitelist)
        if not success:
            return False, f"Regla agregada pero error al aplicar: {msg}"
    
    logger.info(f"=== FIN: add_rule - Regla '{new_rule}' agregada ===")
    return True, f"Regla '{new_rule}' agregada a VLAN {vlan_id}"


def remove_rule(params: Dict[str, Any] = None) -> Tuple[bool, str]:
    """Eliminar una regla de la whitelist de una VLAN."""
    logger.info("=== INICIO: remove_rule ===")
    
    # Validar parámetros
    if not params:
        return False, "Error: No se proporcionaron parámetros"
    
    if not isinstance(params, dict):
        return False, "Error: Los parámetros deben ser un diccionario"
    
    if "vlan_id" not in params:
        return False, "Error: vlan_id requerido"
    
    if "rule" not in params:
        return False, "Error: rule requerido"
    
    # Validar vlan_id
    try:
        vlan_id = int(params["vlan_id"])
    except (ValueError, TypeError):
        return False, f"Error: vlan_id debe ser un número entero, recibido: {params['vlan_id']}"
    
    if vlan_id < 1 or vlan_id > 4094:
        return False, f"Error: vlan_id debe estar entre 1 y 4094, recibido: {vlan_id}"
    
    # Validar rule
    if not isinstance(params["rule"], str):
        return False, f"Error: rule debe ser una cadena, recibido: {type(params['rule']).__name__}"
    
    rule_to_remove = params["rule"].strip()
    
    # VLANs 1 y 2 no permiten whitelist
    if vlan_id in (1, 2):
        return False, f"Error: VLAN {vlan_id} no permite configuración de whitelist"
    
    fw_cfg = _load_firewall_config()
    
    if str(vlan_id) not in fw_cfg.get("vlans", {}):
        return False, f"VLAN {vlan_id} no encontrada en firewall"
    
    # Eliminar regla de la configuración
    whitelist = fw_cfg["vlans"][str(vlan_id)].get("whitelist", [])
    
    if rule_to_remove not in whitelist:
        return False, f"La regla '{rule_to_remove}' no existe en la whitelist"
    
    whitelist.remove(rule_to_remove)
    fw_cfg["vlans"][str(vlan_id)]["whitelist"] = whitelist
    _save_firewall_config(fw_cfg)
    
    # Si la whitelist está habilitada, reaplicar
    if fw_cfg["vlans"][str(vlan_id)].get("whitelist_enabled", False):
        success, msg = _apply_whitelist(vlan_id, whitelist)
        if not success:
            return False, f"Regla eliminada pero error al aplicar: {msg}"
    
    logger.info(f"=== FIN: remove_rule - Regla '{rule_to_remove}' eliminada ===")
    return True, f"Regla '{rule_to_remove}' eliminada de VLAN {vlan_id}"


# -----------------------------
def aislar(params: Dict[str, Any] = None) -> Tuple[bool, str]:
    """Aislar una VLAN bloqueando nuevas conexiones.
    VLAN 1: Bloquea tráfico entrante (-d destination)
    Otras VLANs: Bloquea tráfico saliente (-s source)
    """
    logger.info("=== INICIO: aislar ===")
    
    # Validar parámetros
    if not params:
        return False, "Error: No se proporcionaron parámetros"
    
    if not isinstance(params, dict):
        return False, "Error: Los parámetros deben ser un diccionario"
    
    if "vlan_id" not in params:
        return False, "Error: vlan_id requerido"
    
    # Validar vlan_id
    try:
        vlan_id = int(params["vlan_id"])
    except (ValueError, TypeError):
        return False, f"Error: vlan_id debe ser un número entero, recibido: {params['vlan_id']}"
    
    if vlan_id < 1 or vlan_id > 4094:
        return False, f"Error: vlan_id debe estar entre 1 y 4094, recibido: {vlan_id}"
    
    vlan_id = int(params["vlan_id"])
    
    fw_cfg = _load_firewall_config()
    
    if str(vlan_id) not in fw_cfg.get("vlans", {}):
        return False, f"Error: VLAN {vlan_id} no está configurada en el firewall"
    
    vlan_cfg = fw_cfg["vlans"][str(vlan_id)]
    vlan_ip_network = vlan_cfg.get("ip", "")
    
    if not vlan_ip_network:
        return False, f"Error: VLAN {vlan_id} no tiene IP de red configurada"
    
    # Usar directamente la IP de red con máscara
    ip_mask = vlan_ip_network
    
    # VLAN 1 tiene comportamiento especial: bloquea tráfico HACIA ella (-d)
    if vlan_id == 1:
        logger.info(f"Aislando VLAN 1 con IP {ip_mask} (bloqueando tráfico entrante -d)")
        
        # Verificar si ya está aislada (usando -d)
        success, output = _run_command([
            "iptables", "-C", "FORWARD", "-d", ip_mask, "-m", "conntrack", 
            "--ctstate", "NEW", "-j", "DROP"
        ])
        
        if success:
            logger.info(f"VLAN 1 ya está aislada")
            return True, f"VLAN 1 ya estaba aislada"
        
        # Añadir regla de aislamiento en FORWARD con -d (destination)
        success, output = _run_command([
            "iptables", "-I", "FORWARD", "1", "-d", ip_mask, "-m", "conntrack", 
            "--ctstate", "NEW", "-j", "DROP"
        ])
        
        if not success:
            logger.error(f"Error aislando VLAN 1 en FORWARD: {output}")
            return False, f"Error al aislar VLAN 1: {output}"
        
        # Comprobar si la regla INPUT ya existe
        check_input = _run_command([
            "iptables", "-C", "INPUT", "-d", ip_mask, "-m", "conntrack", 
            "--ctstate", "NEW", "-j", "DROP"
        ])[0]
        
        # Solo añadir regla en INPUT si no existe
        if not check_input:
            success_input, output_input = _run_command([
                "iptables", "-I", "INPUT", "1", "-d", ip_mask, "-m", "conntrack", 
                "--ctstate", "NEW", "-j", "DROP"
            ])
            
            if not success_input:
                logger.warning(f"Error añadiendo regla INPUT para VLAN 1: {output_input}")
        else:
            logger.info("Regla INPUT para VLAN 1 ya existe, saltando...")
        
        msg = "VLAN 1 aislada correctamente. Tráfico entrante bloqueado (saliente permitido)."
    
    else:
        # VLANs normales: bloquear tráfico saliente (-s)
        logger.info(f"Aislando VLAN {vlan_id} con IP {ip_mask} (bloqueando tráfico saliente -s)")
        
        # Verificar si ya está aislada
        success, output = _run_command([
            "iptables", "-C", "FORWARD", "-s", ip_mask, "-m", "conntrack", 
            "--ctstate", "NEW", "-j", "DROP"
        ])
        
        if success:
            logger.info(f"VLAN {vlan_id} ya está aislada")
            return True, f"VLAN {vlan_id} ya estaba aislada"
        
        # Añadir regla de aislamiento al principio de FORWARD con -s (source)
        success, output = _run_command([
            "iptables", "-I", "FORWARD", "1", "-s", ip_mask, "-m", "conntrack", 
            "--ctstate", "NEW", "-j", "DROP"
        ])
        
        if not success:
            logger.error(f"Error aislando VLAN {vlan_id} en FORWARD: {output}")
            return False, f"Error al aislar VLAN {vlan_id}: {output}"
        
        # Comprobar si la regla INPUT ya existe
        check_input = _run_command([
            "iptables", "-C", "INPUT", "-s", ip_mask, "-m", "conntrack", 
            "--ctstate", "NEW", "-j", "DROP"
        ])[0]
        
        # Solo añadir regla en INPUT si no existe
        if not check_input:
            success_input, output_input = _run_command([
                "iptables", "-A", "INPUT", "-s", ip_mask, "-m", "conntrack", 
                "--ctstate", "NEW", "-j", "DROP"
            ])
            
            if not success_input:
                logger.warning(f"Error añadiendo regla INPUT para VLAN {vlan_id}: {output_input}")
        else:
            logger.info(f"Regla INPUT para VLAN {vlan_id} ya existe, saltando...")
        
        msg = f"VLAN {vlan_id} aislada correctamente. Las conexiones nuevas están bloqueadas."
    
    # Actualizar configuración
    vlan_cfg["isolated"] = True
    _save_firewall_config(fw_cfg)
    
    logger.info(f"VLAN {vlan_id} aislada exitosamente")
    logger.info("=== FIN: aislar ===")
    
    return True, msg


def desaislar(params: Dict[str, Any] = None) -> Tuple[bool, str]:
    """Desaislar una VLAN eliminando el bloqueo de nuevas conexiones.
    Nota: VLAN 1 no puede ser desaislada, siempre debe estar aislada cuando el firewall está activo.
    """
    logger.info("=== INICIO: desaislar ===")
    
    # Validar parámetros
    if not params:
        return False, "Error: No se proporcionaron parámetros"
    
    if not isinstance(params, dict):
        return False, "Error: Los parámetros deben ser un diccionario"
    
    if "vlan_id" not in params:
        return False, "Error: vlan_id requerido"
    
    # Validar vlan_id
    try:
        vlan_id = int(params["vlan_id"])
    except (ValueError, TypeError):
        return False, f"Error: vlan_id debe ser un número entero, recibido: {params['vlan_id']}"
    
    if vlan_id < 1 or vlan_id > 4094:
        return False, f"Error: vlan_id debe estar entre 1 y 4094, recibido: {vlan_id}"
    
    # VLAN 1 no puede ser desaislada
    if vlan_id == 1:
        return False, "Error: VLAN 1 no puede ser desaislada. Debe permanecer aislada mientras el firewall esté activo."
    
    fw_cfg = _load_firewall_config()
    
    if str(vlan_id) not in fw_cfg.get("vlans", {}):
        return False, f"Error: VLAN {vlan_id} no está configurada en el firewall"
    
    vlan_cfg = fw_cfg["vlans"][str(vlan_id)]
    vlan_ip_network = vlan_cfg.get("ip", "")
    
    if not vlan_ip_network:
        return False, f"Error: VLAN {vlan_id} no tiene IP de red configurada"
    
    # Usar directamente la IP de red con máscara
    ip_mask = vlan_ip_network
    
    logger.info(f"Desaislando VLAN {vlan_id} con IP {ip_mask}")
    
    # Verificar si está aislada
    success, output = _run_command([
        "iptables", "-C", "FORWARD", "-s", ip_mask, "-m", "conntrack", 
        "--ctstate", "NEW", "-j", "DROP"
    ])
    
    if not success:
        logger.info(f"VLAN {vlan_id} no estaba aislada")
        # Actualizar configuración por si acaso
        vlan_cfg["isolated"] = False
        _save_firewall_config(fw_cfg)
        return True, f"VLAN {vlan_id} no estaba aislada"
    
    # Eliminar regla de aislamiento de FORWARD
    success, output = _run_command([
        "iptables", "-D", "FORWARD", "-s", ip_mask, "-m", "conntrack", 
        "--ctstate", "NEW", "-j", "DROP"
    ])
    
    if not success:
        logger.error(f"Error desaislando VLAN {vlan_id} en FORWARD: {output}")
        return False, f"Error al desaislar VLAN {vlan_id}: {output}"
    
    # Eliminar la regla de INPUT también
    success_input, output_input = _run_command([
        "iptables", "-D", "INPUT", "-s", ip_mask, "-m", "conntrack", 
        "--ctstate", "NEW", "-j", "DROP"
    ])
    
    if not success_input:
        logger.warning(f"Error eliminando regla INPUT para VLAN {vlan_id}: {output_input}")
        # Continuar aunque falle INPUT, FORWARD ya está eliminado
    
    # Actualizar configuración
    vlan_cfg["isolated"] = False
    _save_firewall_config(fw_cfg)
    
    logger.info(f"VLAN {vlan_id} desaislada exitosamente")
    logger.info("=== FIN: desaislar ===")
    
    return True, f"VLAN {vlan_id} desaislada correctamente. El tráfico ha sido restaurado."


# -----------------------------
# Exportar acciones permitidas
# -----------------------------

ALLOWED_ACTIONS = {
    "start": start,
    "stop": stop,
    "restart": restart,
    "status": status,
    "config": config,
    "enable_whitelist": enable_whitelist,
    "disable_whitelist": disable_whitelist,
    "add_rule": add_rule,
    "remove_rule": remove_rule,
    "aislar": aislar,
    "desaislar": desaislar,
}
