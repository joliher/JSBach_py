# app/core/dmz.py

import subprocess
import json
import os
import logging
import ipaddress
from typing import Dict, Any, Tuple, Optional, List
from ..utils.global_functions import create_module_config_directory, create_module_log_directory

# Configurar logging
logger = logging.getLogger(__name__)


# -----------------------------
# Helper para ejecutar comandos con sudo
# -----------------------------

def _run_command(cmd: list) -> Tuple[bool, str]:
    """
    Ejecutar comando con sudo automáticamente.
    
    Args:
        cmd: Lista con el comando y sus argumentos
    
    Returns:
        Tupla (éxito: bool, salida/error: str)
    """
    try:
        full_cmd = ["sudo"] + cmd
        result = subprocess.run(
            full_cmd,
            capture_output=True,
            text=True,
            timeout=30,
            check=False
        )
        
        if result.returncode == 0:
            return True, result.stdout
        else:
            error_msg = result.stderr.strip() or "Comando falló sin mensaje de error"
            logger.error(f"Error ejecutando comando {' '.join(full_cmd)}: {error_msg}")
            return False, error_msg
            
    except subprocess.TimeoutExpired:
        logger.error(f"Timeout ejecutando comando {' '.join(full_cmd)}")
        return False, f"Timeout ejecutando comando"
    except Exception as e:
        logger.error(f"Error inesperado ejecutando comando {' '.join(full_cmd)}: {e}")
        return False, f"Error inesperado: {str(e)}"

# Config file
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
CONFIG_FILE = os.path.join(BASE_DIR, "config", "dmz", "dmz.json")
WAN_CONFIG_FILE = os.path.join(BASE_DIR, "config", "wan", "wan.json")
VLANS_CONFIG_FILE = os.path.join(BASE_DIR, "config", "vlans", "vlans.json")
FIREWALL_CONFIG_FILE = os.path.join(BASE_DIR, "config", "firewall", "firewall.json")
LOG_FILE = os.path.join(BASE_DIR, "logs", "dmz", "actions.log")

# -----------------------------
# Utilidades internas
# -----------------------------

def _ensure_dirs():
    """Crear directorios necesarios."""
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    os.makedirs(os.path.join(BASE_DIR, "logs", "dmz"), exist_ok=True)


def _write_log(message: str):
    """Escribir mensaje en el archivo de log."""
    from datetime import datetime
    _ensure_dirs()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        with open(LOG_FILE, "a") as f:
            f.write(f"[{timestamp}] {message}\n")
    except Exception as e:
        logger.error(f"Error escribiendo en log: {e}")


def _load_config() -> dict:
    """Cargar configuración de DMZ."""
    if not os.path.exists(CONFIG_FILE):
        # Si no existe, crear el archivo con configuración por defecto
        default_config = {"status": 0, "destinations": []}
        _save_config(default_config)
        return default_config
    
    try:
        with open(CONFIG_FILE, "r") as f:
            content = f.read().strip()
            # Si el archivo está vacío, devolver configuración por defecto
            if not content:
                logger.warning("Archivo DMZ config vacío, usando configuración por defecto")
                default_config = {"status": 0, "destinations": []}
                _save_config(default_config)
                return default_config
            
            return json.loads(content)
    except json.JSONDecodeError as e:
        logger.error(f"Error decodificando DMZ config JSON: {e}")
        # Si hay error de JSON, recrear con configuración por defecto
        default_config = {"status": 0, "destinations": []}
        _save_config(default_config)
        return default_config
    except Exception as e:
        logger.error(f"Error cargando DMZ config: {e}")
        return {"status": 0, "destinations": []}


def _save_config(data: dict) -> None:
    """Guardar configuración de DMZ."""
    _ensure_dirs()
    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump(data, f, indent=4)
        logger.info("Configuración DMZ guardada correctamente")
    except Exception as e:
        logger.error(f"Error guardando configuración DMZ: {e}")


def _load_wan_config() -> Optional[dict]:
    """Cargar configuración de WAN para obtener la interfaz."""
    if not os.path.exists(WAN_CONFIG_FILE):
        return None
    try:
        with open(WAN_CONFIG_FILE, "r") as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Error cargando WAN config: {e}")
        return None


def _load_firewall_config() -> Optional[dict]:
    """Cargar configuración del firewall."""
    if not os.path.exists(FIREWALL_CONFIG_FILE):
        return None
    try:
        with open(FIREWALL_CONFIG_FILE, "r") as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Error cargando firewall config: {e}")
        return None


def _load_vlans_config() -> Optional[dict]:
    """Cargar configuración de VLANs."""
    if not os.path.exists(VLANS_CONFIG_FILE):
        return None
    try:
        with open(VLANS_CONFIG_FILE, "r") as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Error cargando VLANs config: {e}")
        return None


def _check_vlans_active() -> bool:
    """Verificar si las VLANs están activas."""
    vlans_cfg = _load_vlans_config()
    if not vlans_cfg:
        return False
    return vlans_cfg.get("status", 0) == 1


def _check_firewall_active() -> bool:
    """Verificar si el firewall está activo."""
    fw_cfg = _load_firewall_config()
    if not fw_cfg:
        return False
    return fw_cfg.get("status", 0) == 1


def _get_wan_interface() -> Optional[str]:
    """Obtener la interfaz WAN de la configuración."""
    wan_cfg = _load_wan_config()
    if not wan_cfg:
        return None
    return wan_cfg.get("interface")


def _get_dmz_network() -> Optional[str]:
    """Obtener la dirección de red DMZ (VLAN 2) de la configuración.
    
    Returns:
        IP de red con máscara (ej: '192.168.2.0/25') o None si no existe
    """
    vlans_cfg = _load_vlans_config()
    if not vlans_cfg:
        return None
    
    for vlan in vlans_cfg.get("vlans", []):
        if vlan.get("id") == 2:
            ip_network = vlan.get("ip_network", "").strip()
            if ip_network:
                return ip_network
            return None
    return None


def _validate_ip_in_dmz(ip: str) -> Tuple[bool, str, str]:
    """Validar que la IP sea válida. Devuelve (válido, mensaje_error, ip_sin_máscara)."""
    
    # Verificar que la IP NO contenga máscara
    if '/' in ip:
        return False, "Error: la IP no debe incluir máscara de red. Introduzca solo la IP (ej: 192.168.2.10)", ""
    
    try:
        # Validar formato de IP
        ip_obj = ipaddress.IPv4Address(ip)
        
        # Validar que el último octeto de la IP no sea 0 ni 255
        last_octet = int(ip.split('.')[-1])
        
        if last_octet == 0 or last_octet == 255:
            return False, "Error: la IP no puede terminar en 0 o 255", ""
        
        return True, "", ip
    except ValueError as e:
        return False, f"Error: formato de IP inválido: {ip} ({str(e)})", ""


# -----------------------------
# Acciones públicas (Admin API)
# -----------------------------

def config(params: Dict[str, Any] = None) -> Tuple[bool, str]:
    """Añadir un destino DMZ (IP/MASK, puerto, protocolo)."""
    logger.info("=== INICIO: dmz config ===")
    create_module_config_directory("dmz")
    create_module_log_directory("dmz")
    
    # Validar parámetros
    if not params:
        return False, "Error: No se proporcionaron parámetros"
    
    if not isinstance(params, dict):
        return False, "Error: Los parámetros deben ser un diccionario"
    
    if "ip" not in params:
        return False, "Error: parámetro 'ip' requerido"
    
    if "port" not in params:
        return False, "Error: parámetro 'port' requerido"
    
    if "protocol" not in params:
        return False, "Error: parámetro 'protocol' requerido"
    
    # Verificar que el firewall esté activo
    if not _check_firewall_active():
        return False, "Error: el firewall debe estar activo para configurar destinos DMZ"
    
    # Validar ip
    if not isinstance(params["ip"], str):
        return False, f"Error: 'ip' debe ser una cadena, recibido: {type(params['ip']).__name__}"
    
    ip = params["ip"].strip()
    
    if not ip:
        return False, "Error: 'ip' no puede estar vacío"
    
    # Validar que la IP esté en la red DMZ (devuelve IP sin máscara)
    valid, error_msg, ip_clean = _validate_ip_in_dmz(ip)
    if not valid:
        return False, error_msg
    
    # Usar la IP sin máscara para el resto de operaciones
    ip = ip_clean
    
    # Validar protocol
    if not isinstance(params["protocol"], str):
        return False, f"Error: 'protocol' debe ser una cadena, recibido: {type(params['protocol']).__name__}"
    
    protocol = params["protocol"].strip().lower()
    
    if not protocol:
        return False, "Error: 'protocol' no puede estar vacío"
    
    if protocol not in ["tcp", "udp"]:
        return False, f"Error: protocolo debe ser 'tcp' o 'udp', recibido: '{protocol}'"
    
    # Validar port
    try:
        port = int(params["port"])
    except (ValueError, TypeError):
        return False, f"Error: 'port' debe ser un número entero, recibido: {params['port']}"
    
    if port < 1 or port > 65535:
        return False, f"Error: puerto debe estar entre 1 y 65535, recibido: {port}"
    
    # Cargar configuración actual
    dmz_cfg = _load_config()
    
    # Verificar si ya existe
    for dest in dmz_cfg.get("destinations", []):
        if dest["ip"] == ip and dest["port"] == port and dest["protocol"] == protocol:
            return False, f"Error: destino {ip}:{port}/{protocol} ya existe"
    
    # Añadir nuevo destino
    new_destination = {
        "ip": ip,
        "port": port,
        "protocol": protocol,
        "isolated": False
    }
    
    if "destinations" not in dmz_cfg:
        dmz_cfg["destinations"] = []
    
    dmz_cfg["destinations"].append(new_destination)
    _save_config(dmz_cfg)
    
    logger.info(f"=== FIN: dmz config - Destino {ip}:{port}/{protocol} añadido ===")
    return True, f"Destino DMZ {ip}:{port}/{protocol} añadido correctamente"


def start(params: Dict[str, Any] = None) -> Tuple[bool, str]:
    """Iniciar DMZ - Aplicar reglas DNAT en cadena custom."""
    logger.info("=== INICIO: dmz start ===")
    _write_log("=== INICIO: DMZ START ===")
    create_module_config_directory("dmz")
    create_module_log_directory("dmz")
    
    # Verificar que VLANs estén activas
    if not _check_vlans_active():
        msg = "Error: las VLANs deben estar activas para iniciar DMZ"
        _write_log(msg)
        return False, msg
    
    # Obtener interfaz WAN
    wan_interface = _get_wan_interface()
    if not wan_interface:
        msg = "Error: no se pudo obtener la interfaz WAN"
        _write_log(msg)
        return False, msg
    
    # Cargar configuración
    dmz_cfg = _load_config()
    destinations = dmz_cfg.get("destinations", [])
    
    if not destinations:
        msg = "⚠️ Error: no hay destinos DMZ configurados. Ve a CONFIG para añadir destinos."
        _write_log(msg)
        return False, msg
    
    # Crear cadena custom DMZ_RULES en tabla nat
    chain_name = "DMZ_RULES"
    success, output = _run_command(["/usr/sbin/iptables", "-t", "nat", "-N", chain_name])
    if not success and "already exists" not in output.lower():
        msg = f"Error creando cadena {chain_name}: {output}"
        _write_log(msg)
        return False, msg
    
    # Limpiar reglas existentes de la cadena
    _run_command(["/usr/sbin/iptables", "-t", "nat", "-F", chain_name])
    _write_log(f"✓ Cadena {chain_name} creada y limpiada")
    
    results = []
    errors = []
    
    # Aplicar reglas DNAT para cada destino en la cadena DMZ_RULES
    for dest in destinations:
        ip = dest["ip"]
        port = dest["port"]
        protocol = dest["protocol"]
        
        # Verificar si la regla ya existe en la cadena DMZ_RULES
        check_cmd = [
            "iptables", "-t", "nat", "-C", chain_name,
            "-i", wan_interface, "-p", protocol, "--dport", str(port),
            "-j", "DNAT", "--to-destination", ip
        ]
        
        success, _ = _run_command(check_cmd)
        
        if success:
            logger.info(f"Regla DMZ {ip}:{port}/{protocol} ya existe en {chain_name}")
            results.append(f"{ip}:{port}/{protocol} - ya existía")
            continue
        
        # Añadir regla DNAT a la cadena DMZ_RULES
        cmd = [
            "iptables", "-t", "nat", "-A", chain_name,
            "-i", wan_interface, "-p", protocol, "--dport", str(port),
            "-j", "DNAT", "--to-destination", ip
        ]
        
        success, output = _run_command(cmd)
        
        if success:
            results.append(f"{ip}:{port}/{protocol} - activado")
            logger.info(f"Regla DMZ {ip}:{port}/{protocol} aplicada en {chain_name}")
            _write_log(f"✅ Regla DNAT aplicada: {ip}:{port}/{protocol} (interfaz: {wan_interface})")
        else:
            errors.append(f"{ip}:{port}/{protocol} - error: {output}")
            logger.error(f"Error aplicando regla DMZ {ip}:{port}/{protocol}: {output}")
            _write_log(f"❌ Error añadiendo regla DNAT {ip}:{port}/{protocol}: {output}")
    
    # Vincular cadena DMZ_RULES a PREROUTING (solo si no está vinculada)
    check_jump = _run_command([
        "iptables", "-t", "nat", "-C", "PREROUTING", "-j", chain_name
    ])[0]
    
    if not check_jump:
        success, output = _run_command([
            "iptables", "-t", "nat", "-A", "PREROUTING", "-j", chain_name
        ])
        
        if success:
            _write_log(f"✅ Cadena {chain_name} vinculada a PREROUTING")
        else:
            msg = f"Error vinculando {chain_name} a PREROUTING: {output}"
            _write_log(f"❌ {msg}")
            return False, msg
    else:
        _write_log(f"✓ Cadena {chain_name} ya estaba vinculada a PREROUTING")
    
    # Actualizar estado
    dmz_cfg["status"] = 1
    _save_config(dmz_cfg)
    
    msg = "DMZ iniciado:\n" + "\n".join(results)
    if errors:
        msg += "\n\nErrores:\n" + "\n".join(errors)
        _write_log(f"❌ DMZ iniciado con errores: {'; '.join(errors)}")
        _write_log("=== FIN: DMZ START (CON ERRORES) ===")
    else:
        _write_log(f"✅ DMZ iniciado correctamente: {'; '.join(results)}")
        _write_log("=== FIN: DMZ START (ÉXITO) ===")
    
    logger.info("=== FIN: dmz start ===")
    return len(errors) == 0, msg


def stop(params: Dict[str, Any] = None) -> Tuple[bool, str]:
    """Detener DMZ - Eliminar reglas DNAT y cadena custom."""
    logger.info("=== INICIO: dmz stop ===")
    _write_log("=== INICIO: DMZ STOP ===")
    create_module_config_directory("dmz")
    create_module_log_directory("dmz")
    
    # Obtener interfaz WAN
    wan_interface = _get_wan_interface()
    if not wan_interface:
        msg = "Error: no se pudo obtener la interfaz WAN"
        _write_log(msg)
        return False, msg
    
    # Cargar configuración
    dmz_cfg = _load_config()
    destinations = dmz_cfg.get("destinations", [])    
    _write_log(f"Eliminando reglas DNAT de {len(destinations)} destino(s)...")    
    if not destinations:
        dmz_cfg["status"] = 0
        _save_config(dmz_cfg)
        return True, "DMZ detenido (no había destinos configurados)"
    
    results = []
    chain_name = "DMZ_RULES"
    
    # Desvincular cadena DMZ_RULES de PREROUTING
    _write_log(f"Desvinculando cadena {chain_name} de PREROUTING...")
    for attempt in range(5):  # Intentar eliminar hasta 5 veces por si hay duplicados
        success, output = _run_command([
            "iptables", "-t", "nat", "-D", "PREROUTING", "-j", chain_name
        ])
        if not success:
            break  # No hay más reglas de salto
        _write_log(f"✓ Salto a {chain_name} eliminado (intento {attempt + 1})")
    
    # Limpiar reglas de la cadena DMZ_RULES
    success, output = _run_command(["/usr/sbin/iptables", "-t", "nat", "-F", chain_name])
    if success:
        _write_log(f"✓ Reglas de {chain_name} limpiadas")
    
    # Eliminar la cadena DMZ_RULES
    success, output = _run_command(["/usr/sbin/iptables", "-t", "nat", "-X", chain_name])
    if success:
        _write_log(f"✅ Cadena {chain_name} eliminada")
        results.append(f"Cadena {chain_name} eliminada correctamente")
    elif "does not exist" in output.lower() or "no chain" in output.lower():
        _write_log(f"✓ Cadena {chain_name} no existía")
    else:
        _write_log(f"⚠️ Error eliminando cadena {chain_name}: {output}")
    
    # Eliminar aislamientos si existen
    for dest in destinations:
        ip = dest["ip"]
        port = dest["port"]
        protocol = dest["protocol"]
        isolated = dest.get("isolated", False)
        
        if isolated:
            logger.info(f"Desaislando {ip}...")
            # Eliminar regla de aislamiento de FORWARD
            desaislar_forward = [
                "iptables", "-D", "FORWARD", "-s", ip,
                "-m", "conntrack", "--ctstate", "NEW", "-j", "DROP"
            ]
            success_forward, _ = _run_command(desaislar_forward)
            if success_forward:
                _write_log(f"✅ Eliminado aislamiento de {ip} (FORWARD)")
            
            # Eliminar regla de aislamiento de INPUT
            desaislar_input = [
                "iptables", "-D", "INPUT", "-s", ip,
                "-m", "conntrack", "--ctstate", "NEW", "-j", "DROP"
            ]
            success_input, _ = _run_command(desaislar_input)
            if success_input:
                _write_log(f"✅ Eliminado aislamiento de {ip} (INPUT)")
            
            dest["isolated"] = False
        
        results.append(f"{ip}:{port}/{protocol} - eliminado")
        _write_log(f"✅ Regla DNAT eliminada: {ip}:{port}/{protocol}")
    
    # Actualizar estado
    dmz_cfg["status"] = 0
    _save_config(dmz_cfg)
    
    msg = "DMZ detenido:\n" + "\n".join(results)
    _write_log(f"✅ DMZ detenido correctamente: {'; '.join(results)}")
    _write_log("=== FIN: DMZ STOP (ÉXITO) ===")
    
    logger.info("=== FIN: dmz stop ===")
    return True, msg


def restart(params: Dict[str, Any] = None) -> Tuple[bool, str]:
    """Reiniciar DMZ (detener y arrancar)."""
    logger.info("=== INICIO: dmz restart ===")
    create_module_config_directory("dmz")
    create_module_log_directory("dmz")
    
    _write_log("=== INICIO: DMZ RESTART ===")
    
    # Detener DMZ
    success_stop, msg_stop = stop(params)
    if not success_stop:
        _write_log(f"❌ Error al detener DMZ durante restart: {msg_stop}")
        logger.error(f"Error en stop durante restart: {msg_stop}")
        return False, f"Error al detener DMZ: {msg_stop}"
    
    _write_log("✅ DMZ detenido correctamente")
    
    # Iniciar DMZ
    success_start, msg_start = start(params)
    if not success_start:
        _write_log(f"❌ Error al iniciar DMZ durante restart: {msg_start}")
        logger.error(f"Error en start durante restart: {msg_start}")
        return False, f"Error al iniciar DMZ: {msg_start}"
    
    _write_log("✅ DMZ iniciado correctamente")
    _write_log("=== FIN: DMZ RESTART (ÉXITO) ===")
    
    logger.info("=== FIN: dmz restart (éxito) ===")
    return True, "DMZ reiniciado correctamente"


def status(params: Dict[str, Any] = None) -> Tuple[bool, str]:
    """Obtener estado de DMZ."""
    create_module_config_directory("dmz")
    create_module_log_directory("dmz")
    
    try:
        dmz_cfg = _load_config()
        
        # Verificar si VLANs están activas
        vlans_active = _check_vlans_active()
        
        # Añadir información de VLANs y WAN
        wan_interface = _get_wan_interface()
        
        response = {
            "status": dmz_cfg.get("status", 0),
            "destinations": dmz_cfg.get("destinations", []),
            "vlans_active": vlans_active,
            "wan_interface": wan_interface or "no configurada"
        }
        
        # Logging simplificado solo si hay destinos configurados
        destinations = dmz_cfg.get("destinations", [])
        if destinations:
            status_text = "ACTIVO" if dmz_cfg.get("status", 0) == 1 else "INACTIVO"
            _write_log(f"Estado DMZ: {status_text} ({len(destinations)} destino(s) configurado(s))")
        
        return True, json.dumps(response)
    except Exception as e:
        logger.error(f"Error en dmz status: {e}")
        # Devolver respuesta por defecto en caso de error
        error_response = {
            "status": 0,
            "destinations": [],
            "vlans_active": False,
            "wan_interface": "error al cargar"
        }
        return True, json.dumps(error_response)


def aislar(params: Dict[str, Any] = None) -> Tuple[bool, str]:
    """Aislar un destino DMZ específico bloqueando tráfico hacia él."""
    logger.info("=== INICIO: dmz aislar ===")
    
    # Validar parámetros
    if not params:
        return False, "Error: No se proporcionaron parámetros"
    
    if not isinstance(params, dict):
        return False, "Error: Los parámetros deben ser un diccionario"
    
    if "ip" not in params:
        return False, "Error: parámetro 'ip' requerido"
    
    if "port" not in params:
        return False, "Error: parámetro 'port' requerido"
    
    if "protocol" not in params:
        return False, "Error: parámetro 'protocol' requerido"
    
    # Validar ip
    if not isinstance(params["ip"], str):
        return False, f"Error: 'ip' debe ser una cadena, recibido: {type(params['ip']).__name__}"
    
    ip = params["ip"].strip()
    
    if not ip:
        return False, "Error: 'ip' no puede estar vacío"
    
    # Validar protocol
    if not isinstance(params["protocol"], str):
        return False, f"Error: 'protocol' debe ser una cadena, recibido: {type(params['protocol']).__name__}"
    
    protocol = params["protocol"].strip().lower()
    
    if not protocol:
        return False, "Error: 'protocol' no puede estar vacío"
    
    if protocol not in ["tcp", "udp"]:
        return False, f"Error: protocolo debe ser 'tcp' o 'udp', recibido: '{protocol}'"
    
    # Validar port
    try:
        port = int(params["port"])
    except (ValueError, TypeError):
        return False, f"Error: 'port' debe ser un número entero, recibido: {params['port']}"
    
    if port < 1 or port > 65535:
        return False, f"Error: puerto debe estar entre 1 y 65535, recibido: {port}"
    
    # Cargar configuración
    dmz_cfg = _load_config()
    destinations = dmz_cfg.get("destinations", [])
    
    # Buscar el destino
    target_dest = None
    for dest in destinations:
        if dest["ip"] == ip and dest["port"] == port and dest["protocol"] == protocol:
            target_dest = dest
            break
    
    if not target_dest:
        return False, f"Error: destino {ip}:{port}/{protocol} no encontrado"
    
    if target_dest.get("isolated", False):
        return True, f"Destino {ip}:{port}/{protocol} ya estaba aislado"
    
    # Verificar si la regla FORWARD ya existe (bloquear tráfico desde esta IP)
    check_forward = _run_command([
        "iptables", "-C", "FORWARD", "-s", ip,
        "-m", "conntrack", "--ctstate", "NEW", "-j", "DROP"
    ])[0]
    
    if check_forward:
        target_dest["isolated"] = True
        _save_config(dmz_cfg)
        return True, f"Destino {ip}:{port}/{protocol} ya estaba aislado"
    
    # Añadir regla de aislamiento en FORWARD (bloquear tráfico desde esta IP)
    cmd_forward = [
        "iptables", "-I", "FORWARD", "1", "-s", ip,
        "-m", "conntrack", "--ctstate", "NEW", "-j", "DROP"
    ]
    
    success_forward, output_forward = _run_command(cmd_forward)
    
    if not success_forward:
        logger.error(f"Error aislando {ip} en FORWARD: {output_forward}")
        return False, f"Error al aislar {ip}: {output_forward}"
    
    logger.info(f"Regla FORWARD añadida para aislar {ip}")
    
    # Añadir regla de aislamiento en INPUT (bloquear tráfico desde esta IP hacia el router)
    check_input = _run_command([
        "iptables", "-C", "INPUT", "-s", ip,
        "-m", "conntrack", "--ctstate", "NEW", "-j", "DROP"
    ])[0]
    
    if not check_input:
        cmd_input = [
            "iptables", "-A", "INPUT", "-s", ip,
            "-m", "conntrack", "--ctstate", "NEW", "-j", "DROP"
        ]
        
        success_input, output_input = _run_command(cmd_input)
        
        if success_input:
            logger.info(f"Regla INPUT añadida para aislar {ip}")
        else:
            logger.warning(f"Error añadiendo regla INPUT para {ip}: {output_input}")
    else:
        logger.info(f"Regla INPUT para {ip} ya existía")
    
    # Marcar como aislado en configuración
    target_dest["isolated"] = True
    _save_config(dmz_cfg)
    
    logger.info(f"=== FIN: dmz aislar - {ip}:{port}/{protocol} aislado ===")
    return True, f"Destino {ip}:{port}/{protocol} aislado correctamente"


def desaislar(params: Dict[str, Any] = None) -> Tuple[bool, str]:
    """Desaislar un destino DMZ específico."""
    logger.info("=== INICIO: dmz desaislar ===")
    
    # Validar parámetros
    if not params:
        return False, "Error: No se proporcionaron parámetros"
    
    if not isinstance(params, dict):
        return False, "Error: Los parámetros deben ser un diccionario"
    
    if "ip" not in params:
        return False, "Error: parámetro 'ip' requerido"
    
    if "port" not in params:
        return False, "Error: parámetro 'port' requerido"
    
    if "protocol" not in params:
        return False, "Error: parámetro 'protocol' requerido"
    
    # Validar ip
    if not isinstance(params["ip"], str):
        return False, f"Error: 'ip' debe ser una cadena, recibido: {type(params['ip']).__name__}"
    
    ip = params["ip"].strip()
    
    if not ip:
        return False, "Error: 'ip' no puede estar vacío"
    
    # Validar protocol
    if not isinstance(params["protocol"], str):
        return False, f"Error: 'protocol' debe ser una cadena, recibido: {type(params['protocol']).__name__}"
    
    protocol = params["protocol"].strip().lower()
    
    if not protocol:
        return False, "Error: 'protocol' no puede estar vacío"
    
    if protocol not in ["tcp", "udp"]:
        return False, f"Error: protocolo debe ser 'tcp' o 'udp', recibido: '{protocol}'"
    
    # Validar port
    try:
        port = int(params["port"])
    except (ValueError, TypeError):
        return False, f"Error: 'port' debe ser un número entero, recibido: {params['port']}"
    
    if port < 1 or port > 65535:
        return False, f"Error: puerto debe estar entre 1 y 65535, recibido: {port}"
    
    # Cargar configuración
    dmz_cfg = _load_config()
    destinations = dmz_cfg.get("destinations", [])
    
    # Buscar el destino
    target_dest = None
    for dest in destinations:
        if dest["ip"] == ip and dest["port"] == port and dest["protocol"] == protocol:
            target_dest = dest
            break
    
    if not target_dest:
        return False, f"Error: destino {ip}:{port}/{protocol} no encontrado"
    
    if not target_dest.get("isolated", False):
        return True, f"Destino {ip}:{port}/{protocol} no estaba aislado"
    
    # Eliminar regla de aislamiento de FORWARD
    cmd_forward = [
        "iptables", "-D", "FORWARD", "-s", ip,
        "-m", "conntrack", "--ctstate", "NEW", "-j", "DROP"
    ]
    
    success_forward, output_forward = _run_command(cmd_forward)
    
    if not success_forward:
        logger.warning(f"Error desaislando {ip} de FORWARD: {output_forward}")
    else:
        logger.info(f"Regla FORWARD eliminada para {ip}")
    
    # Eliminar regla de aislamiento de INPUT
    cmd_input = [
        "iptables", "-D", "INPUT", "-s", ip,
        "-m", "conntrack", "--ctstate", "NEW", "-j", "DROP"
    ]
    
    success_input, output_input = _run_command(cmd_input)
    
    if not success_input:
        logger.warning(f"Error desaislando {ip} de INPUT: {output_input}")
    else:
        logger.info(f"Regla INPUT eliminada para {ip}")
    
    # Marcar como no aislado en configuración
    target_dest["isolated"] = False
    _save_config(dmz_cfg)
    
    logger.info(f"=== FIN: dmz desaislar - {ip}:{port}/{protocol} desaislado ===")
    return True, f"Destino {ip}:{port}/{protocol} desaislado correctamente"


def eliminar(params: Dict[str, Any] = None) -> Tuple[bool, str]:
    """Eliminar un destino DMZ."""
    logger.info("=== INICIO: dmz eliminar ===")
    
    # Validar parámetros
    if not params:
        return False, "Error: No se proporcionaron parámetros"
    
    if not isinstance(params, dict):
        return False, "Error: Los parámetros deben ser un diccionario"
    
    if "ip" not in params:
        return False, "Error: parámetro 'ip' requerido"
    
    if "port" not in params:
        return False, "Error: parámetro 'port' requerido"
    
    if "protocol" not in params:
        return False, "Error: parámetro 'protocol' requerido"
    
    # Validar ip
    if not isinstance(params["ip"], str):
        return False, f"Error: 'ip' debe ser una cadena, recibido: {type(params['ip']).__name__}"
    
    ip = params["ip"].strip()
    
    if not ip:
        return False, "Error: 'ip' no puede estar vacío"
    
    # Validar protocol
    if not isinstance(params["protocol"], str):
        return False, f"Error: 'protocol' debe ser una cadena, recibido: {type(params['protocol']).__name__}"
    
    protocol = params["protocol"].strip().lower()
    
    if not protocol:
        return False, "Error: 'protocol' no puede estar vacío"
    
    if protocol not in ["tcp", "udp"]:
        return False, f"Error: protocolo debe ser 'tcp' o 'udp', recibido: '{protocol}'"
    
    # Validar port
    try:
        port = int(params["port"])
    except (ValueError, TypeError):
        return False, f"Error: 'port' debe ser un número entero, recibido: {params['port']}"
    
    if port < 1 or port > 65535:
        return False, f"Error: puerto debe estar entre 1 y 65535, recibido: {port}"
    
    # Cargar configuración
    dmz_cfg = _load_config()
    destinations = dmz_cfg.get("destinations", [])
    
    # Buscar y eliminar el destino
    target_dest = None
    for dest in destinations:
        if dest["ip"] == ip and dest["port"] == port and dest["protocol"] == protocol:
            target_dest = dest
            break
    
    if not target_dest:
        return False, f"Error: destino {ip}:{port}/{protocol} no encontrado"
    
    # Si está aislado, desaislar primero (eliminar reglas de FORWARD e INPUT)
    if target_dest.get("isolated", False):
        # Eliminar de FORWARD
        desaislar_forward = [
            "iptables", "-D", "FORWARD", "-s", ip,
            "-m", "conntrack", "--ctstate", "NEW", "-j", "DROP"
        ]
        success_forward, _ = _run_command(desaislar_forward)
        if success_forward:
            logger.info(f"Regla FORWARD de aislamiento eliminada para {ip}")
        
        # Eliminar de INPUT
        desaislar_input = [
            "iptables", "-D", "INPUT", "-s", ip,
            "-m", "conntrack", "--ctstate", "NEW", "-j", "DROP"
        ]
        success_input, _ = _run_command(desaislar_input)
        if success_input:
            logger.info(f"Regla INPUT de aislamiento eliminada para {ip}")
    
    # Si DMZ está activo, eliminar regla DNAT de la cadena DMZ_RULES
    if dmz_cfg.get("status", 0) == 1:
        wan_interface = _get_wan_interface()
        if wan_interface:
            chain_name = "DMZ_RULES"
            dnat_cmd = [
                "iptables", "-t", "nat", "-D", chain_name,
                "-i", wan_interface, "-p", protocol, "--dport", str(port),
                "-j", "DNAT", "--to-destination", ip
            ]
            success, output = _run_command(dnat_cmd)
            if success:
                logger.info(f"Regla DNAT eliminada de {chain_name}: {ip}:{port}/{protocol}")
            else:
                logger.warning(f"Error eliminando regla DNAT de {chain_name}: {output}")
    
    # Eliminar de la configuración
    destinations.remove(target_dest)
    dmz_cfg["destinations"] = destinations
    _save_config(dmz_cfg)
    
    logger.info(f"=== FIN: dmz eliminar - {ip}:{port}/{protocol} eliminado ===")
    return True, f"Destino {ip}:{port}/{protocol} eliminado correctamente"


# Diccionario de acciones permitidas
ALLOWED_ACTIONS = {
    "config": config,
    "start": start,
    "stop": stop,
    "restart": restart,
    "status": status,
    "aislar": aislar,
    "desaislar": desaislar,
    "eliminar": eliminar
}
