# app/core/firewall.py - Versión simplificada

import subprocess
import json
import os
import logging
from typing import Dict, Any, Tuple, List
from ..utils.global_functions import create_module_config_directory, create_module_log_directory, log_action

# Configurar logging
logger = logging.getLogger(__name__)

# Directorios
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
CONFIG_DIR = os.path.join(BASE_DIR, "config", "firewall")
VLANS_CONFIG_FILE = os.path.join(BASE_DIR, "config", "vlans", "vlans.json")
WAN_CONFIG_FILE = os.path.join(BASE_DIR, "config", "wan", "wan.json")
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


def _load_wan_config() -> dict:
    """Cargar configuración de WAN."""
    if not os.path.exists(WAN_CONFIG_FILE):
        return None
    try:
        with open(WAN_CONFIG_FILE, "r") as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Error cargando WAN config: {e}")
        return None


def _check_wan_configured() -> bool:
    """Verificar si la WAN está configurada (tiene interfaz asignada)."""
    wan_cfg = _load_wan_config()
    if not wan_cfg:
        return False
    return bool(wan_cfg.get("interface"))


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


def _ensure_security_chain():
    """Crear cadena SECURITY_DROPS_FIREWALL si no existe y vincularla a FORWARD.
    GARANTIZA que SECURITY_DROPS_FIREWALL esté en posición 1 de FORWARD.
    """
    # Verificar si la cadena existe
    success, _ = _run_command(["iptables", "-L", "SECURITY_DROPS_FIREWALL", "-n"])
    
    if not success:
        # Crear cadena
        _run_command(["iptables", "-N", "SECURITY_DROPS_FIREWALL"])
        logger.info("Cadena SECURITY_DROPS_FIREWALL creada")
    
    # Verificar si ya está vinculada a FORWARD
    success, output = _run_command([
        "iptables", "-C", "FORWARD", "-j", "SECURITY_DROPS_FIREWALL"
    ])
    
    if not success:
        # No está vinculada, vincular en posición 1
        _run_command(["iptables", "-I", "FORWARD", "1", "-j", "SECURITY_DROPS_FIREWALL"])
        logger.info("Cadena SECURITY_DROPS_FIREWALL vinculada a FORWARD en posición 1")
    else:
        # Ya está vinculada, verificar que esté en posición 1
        success, output = _run_command(["iptables", "-L", "FORWARD", "-n", "--line-numbers"])
        if success:
            lines = output.strip().split('\n')
            for line in lines:
                if 'SECURITY_DROPS_FIREWALL' in line:
                    parts = line.split()
                    if parts and parts[0].isdigit():
                        position = int(parts[0])
                        if position != 1:
                            # Está en posición incorrecta, reposicionar
                            logger.warning(f"SECURITY_DROPS_FIREWALL en posición {position}, reposicionando a 1")
                            _run_command(["iptables", "-D", "FORWARD", "-j", "SECURITY_DROPS_FIREWALL"])
                            _run_command(["iptables", "-I", "FORWARD", "1", "-j", "SECURITY_DROPS_FIREWALL"])
                            logger.info("Cadena SECURITY_DROPS_FIREWALL reposicionada a posición 1")
                    break


def _ensure_input_protection_chain():
    """Crear cadena INPUT_PROTECTION para reglas de protección WAN.
    GARANTIZA que INPUT_PROTECTION esté en posición 1 de INPUT.
    """
    # Verificar si la cadena existe
    success, _ = _run_command(["iptables", "-L", "INPUT_PROTECTION", "-n"])
    
    if not success:
        # Crear cadena
        _run_command(["iptables", "-N", "INPUT_PROTECTION"])
        logger.info("Cadena INPUT_PROTECTION creada")
    
    # Verificar si ya está vinculada a INPUT
    success, output = _run_command([
        "iptables", "-C", "INPUT", "-j", "INPUT_PROTECTION"
    ])
    
    if not success:
        # No está vinculada, vincular en posición 1
        _run_command(["iptables", "-I", "INPUT", "1", "-j", "INPUT_PROTECTION"])
        logger.info("Cadena INPUT_PROTECTION vinculada a INPUT en posición 1")
    else:
        # Ya está vinculada, verificar que esté en posición 1
        success, output = _run_command(["iptables", "-L", "INPUT", "-n", "--line-numbers"])
        if success:
            lines = output.strip().split('\n')
            for line in lines:
                if 'INPUT_PROTECTION' in line:
                    parts = line.split()
                    if parts and parts[0].isdigit():
                        position = int(parts[0])
                        if position != 1:
                            # Está en posición incorrecta, reposicionar
                            logger.warning(f"INPUT_PROTECTION en posición {position}, reposicionando a 1")
                            _run_command(["iptables", "-D", "INPUT", "-j", "INPUT_PROTECTION"])
                            _run_command(["iptables", "-I", "INPUT", "1", "-j", "INPUT_PROTECTION"])
                            logger.info("Cadena INPUT_PROTECTION reposicionada a posición 1")
                    break


def _ensure_input_restriction_chain():
    """Crear cadena INPUT_RESTRICTIONS para restricciones de VLANs.
    GARANTIZA que INPUT_RESTRICTIONS esté en posición 2 de INPUT (después de INPUT_PROTECTION).
    """
    # Verificar si la cadena existe
    success, _ = _run_command(["iptables", "-L", "INPUT_RESTRICTIONS", "-n"])
    
    if not success:
        # Crear cadena
        _run_command(["iptables", "-N", "INPUT_RESTRICTIONS"])
        logger.info("Cadena INPUT_RESTRICTIONS creada")
    
    # Verificar posición de ambas cadenas en INPUT
    success, output = _run_command(["iptables", "-L", "INPUT", "-n", "--line-numbers"])
    
    protection_pos = None
    restriction_pos = None
    
    if success:
        lines = output.strip().split('\n')
        for line in lines:
            parts = line.split()
            if parts and parts[0].isdigit():
                position = int(parts[0])
                if 'INPUT_PROTECTION' in line:
                    protection_pos = position
                elif 'INPUT_RESTRICTIONS' in line:
                    restriction_pos = position
    
    # Si RESTRICTIONS no está vinculada, vincularla
    if restriction_pos is None:
        # Determinar posición: después de PROTECTION si existe, sino en posición 1
        target_pos = protection_pos + 1 if protection_pos else 1
        _run_command(["iptables", "-I", "INPUT", str(target_pos), "-j", "INPUT_RESTRICTIONS"])
        logger.info(f"Cadena INPUT_RESTRICTIONS vinculada a INPUT en posición {target_pos}")
    else:
        # RESTRICTIONS está vinculada, verificar orden correcto
        if protection_pos and restriction_pos <= protection_pos:
            # RESTRICTIONS está antes o al mismo nivel que PROTECTION, reposicionar
            logger.warning(f"INPUT_RESTRICTIONS en posición {restriction_pos} (antes de PROTECTION en {protection_pos}), reposicionando")
            _run_command(["iptables", "-D", "INPUT", "-j", "INPUT_RESTRICTIONS"])
            _run_command(["iptables", "-I", "INPUT", str(protection_pos + 1), "-j", "INPUT_RESTRICTIONS"])
            logger.info(f"Cadena INPUT_RESTRICTIONS reposicionada después de INPUT_PROTECTION")


def _get_wan_interface() -> str:
    """Obtener la interfaz WAN de la configuración."""
    if not os.path.exists(WAN_CONFIG_FILE):
        return None
    try:
        with open(WAN_CONFIG_FILE, "r") as f:
            wan_cfg = json.load(f)
            return wan_cfg.get("interface")
    except Exception as e:
        logger.error(f"Error cargando WAN config: {e}")
        return None


def _setup_wan_protection():
    """Proteger el router desde WAN: permitir solo ICMP (ping), bloquear todo lo demás.
    Usa cadena INPUT_PROTECTION para garantizar evaluación controlada.
    """
    wan_if = _get_wan_interface()
    
    if not wan_if:
        logger.warning("No se pudo obtener interfaz WAN, saltando protección WAN")
        return
    
    logger.info(f"Configurando protección WAN en interfaz {wan_if}")
    
    # Asegurar que la cadena INPUT_PROTECTION existe y está bien posicionada
    _ensure_input_protection_chain()
    
    # Limpiar reglas existentes en INPUT_PROTECTION
    _run_command(["iptables", "-F", "INPUT_PROTECTION"])
    
    # Permitir ICMP (ping) desde WAN en posición 1
    success = _run_command([
        "iptables", "-I", "INPUT_PROTECTION", "1", "-i", wan_if, "-p", "icmp", "--icmp-type", "echo-request", "-j", "ACCEPT"
    ])[0]
    if success:
        logger.info(f"✓ Permitido ICMP (ping) desde WAN ({wan_if})")
    else:
        logger.error(f"Error permitiendo ICMP desde WAN")
        return
    
    # Bloquear todo lo demás desde WAN (append al final de la cadena)
    success = _run_command([
        "iptables", "-A", "INPUT_PROTECTION", "-i", wan_if, "-j", "DROP"
    ])[0]
    if success:
        logger.info(f"✓ Bloqueado todo tráfico desde WAN ({wan_if}) excepto ICMP")
    else:
        logger.error(f"Error bloqueando tráfico desde WAN")
        return
    
    logger.info("Protección WAN configurada correctamente en cadena INPUT_PROTECTION")


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
    
    # Verificar que WAN esté configurada (dependencia obligatoria)
    if not _check_wan_configured():
        msg = "Error: la WAN debe estar configurada antes de iniciar el firewall"
        logger.error(msg)
        log_action("firewall", "start", "error", msg)
        return False, msg
    
    # Crear directorio de logs y asegurar permisos
    create_module_log_directory("firewall")
    create_module_config_directory("firewall")
    
    vlans_cfg = _load_vlans_config()
    vlans = vlans_cfg.get("vlans", [])
    
    if not vlans:
        msg = "No hay VLANs configuradas. Configure VLANs primero."
        logger.warning(msg)
        return False, msg
    
    # Asegurar que existe la cadena de seguridad
    _ensure_security_chain()
    
    # Asegurar que existen las cadenas de protección INPUT
    _ensure_input_protection_chain()
    _ensure_input_restriction_chain()
    
    # Proteger el router desde WAN (permitir solo ping, bloquear resto)
    _setup_wan_protection()
    
    fw_cfg = _load_firewall_config()
    if "vlans" not in fw_cfg:
        fw_cfg["vlans"] = {}
    
    # Limpiar reglas anteriores del firewall (solo las cadenas VLAN)
    # NO tocar SECURITY_DROPS ni reglas de otros módulos
    for vlan_id in list(fw_cfg.get("vlans", {}).keys()):
        chain_name = f"VLAN_{vlan_id}"
        vlan_ip = fw_cfg["vlans"][vlan_id].get("ip", "")
        
        # Desvincular de FORWARD si existe
        if vlan_ip:
            _run_command([
                "iptables", "-D", "FORWARD", "-s", vlan_ip, "-j", chain_name
            ])
        
        # Limpiar y eliminar cadena
        _run_command(["/usr/sbin/iptables", "-F", chain_name])
        _run_command(["/usr/sbin/iptables", "-X", chain_name])
    
    logger.info("Cadenas VLAN anteriores limpiadas, SECURITY_DROPS preservada")
    
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
    
    # Aislar siempre VLAN 1 cuando el firewall está activo
    if "1" in fw_cfg["vlans"]:
        vlan1_ip = fw_cfg["vlans"]["1"].get("ip", "")
        if vlan1_ip:
            if '/' not in vlan1_ip:
                ip_mask = f"{vlan1_ip}/24"
            else:
                ip_mask = vlan1_ip
            # Insertar/forzar reglas de aislamiento (DROP entrante hacia VLAN 1)
            # Solo en SECURITY_DROPS_FIREWALL, no en INPUT_RESTRICTIONS para evitar duplicación
            _run_command([
                "iptables", "-I", "SECURITY_DROPS_FIREWALL", "1", "-d", ip_mask, "-m", "conntrack",
                "--ctstate", "NEW", "-j", "DROP"
            ])
            fw_cfg["vlans"]["1"]["isolated"] = True
            _save_firewall_config(fw_cfg)
            results.append("VLAN 1: Aislada (forzado en start)")

    # Restringir siempre todas las VLANs excepto VLAN 1 al iniciar
    logger.info("Aplicando restricciones de VLANs (todas excepto 1)...")
    applied_restrictions = []
    for vlan_id in list(fw_cfg.get("vlans", {}).keys()):
        if vlan_id == "1":
            continue
        vlan_cfg = fw_cfg["vlans"][vlan_id]
        vlan_cfg["restricted"] = False  # forzar ejecución de restrict
        success, msg = restrict({"vlan_id": int(vlan_id), "suppress_log": True})
        if success:
            applied_restrictions.append(vlan_id)
            results.append(f"VLAN {vlan_id}: Restricción aplicada")
        else:
            logger.warning(f"No se pudo restringir VLAN {vlan_id}: {msg}")

    # Sincronizar firewall.json con las restricciones aplicadas (un solo guardado)
    fw_cfg_final = _load_firewall_config()
    for vlan_id in applied_restrictions:
        if vlan_id in fw_cfg_final.get("vlans", {}):
            fw_cfg_final["vlans"][vlan_id]["restricted"] = True
    _save_firewall_config(fw_cfg_final)
    
    if not results:
        msg = "No se pudo habilitar ninguna VLAN\n" + "\n".join(errors)
        logger.error(msg)
        log_action("firewall", f"Error en start: {msg}", "ERROR")
        return False, msg
    
    msg = "Firewall iniciado:\n" + "\n".join(results)
    if errors:
        msg += "\n\nErrores:\n" + "\n".join(errors)
    
    logger.info("=== FIN: firewall start ===")
    
    # Registrar acción exitosa en actions.log
    log_action("firewall", f"Firewall iniciado correctamente:\n{msg}")
    
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
    
    # Primero, eliminar todas las reglas de aislamiento y restricciones
    for vlan_id, vlan_data in vlans.items():
        vlan_ip = vlan_data.get("ip", "")
        isolated = vlan_data.get("isolated", False)
        
        if vlan_ip:
            # Calcular IP/máscara
            if '/' not in vlan_ip:
                ip_mask = f"{vlan_ip}/24"
            else:
                ip_mask = vlan_ip
            
            # Eliminar aislamiento (todas menos VLAN 1, que permanece aislada por política)
            if isolated and vlan_id != "1":
                logger.info(f"Desaislando VLAN {vlan_id}...")
                
                _run_command([
                    "iptables", "-D", "SECURITY_DROPS_FIREWALL", "-s", ip_mask, "-m", "conntrack", 
                    "--ctstate", "NEW", "-j", "DROP"
                ])
                _run_command([
                    "iptables", "-D", "INPUT", "-s", ip_mask, "-m", "conntrack", 
                    "--ctstate", "NEW", "-j", "DROP"
                ])
                
                vlan_data["isolated"] = False
                logger.info(f"VLAN {vlan_id} desaislada")
            elif vlan_id == "1" and isolated:
                logger.info("VLAN 1 permanece aislada (política fija)")
            
            # Eliminar restricciones de todas las VLANs (stop debe dejar sin restricciones)
            logger.info(f"Desrestringiendo VLAN {vlan_id}...")
            if int(vlan_id) in [1, 2]:
                _run_command([
                    "iptables", "-D", "INPUT_RESTRICTIONS", "-s", ip_mask, "-j", "DROP"
                ])
            else:
                _run_command([
                    "iptables", "-D", "INPUT_RESTRICTIONS", "-s", ip_mask, "-p", "udp", "--dport", "67:68", "-j", "ACCEPT"
                ])
                _run_command([
                    "iptables", "-D", "INPUT_RESTRICTIONS", "-s", ip_mask, "-p", "udp", "--dport", "53", "-j", "ACCEPT"
                ])
                _run_command([
                    "iptables", "-D", "INPUT_RESTRICTIONS", "-s", ip_mask, "-p", "tcp", "--dport", "53", "-j", "ACCEPT"
                ])
                _run_command([
                    "iptables", "-D", "INPUT_RESTRICTIONS", "-s", ip_mask, "-p", "icmp", "-j", "ACCEPT"
                ])
                _run_command([
                    "iptables", "-D", "INPUT_RESTRICTIONS", "-s", ip_mask, "-j", "DROP"
                ])
            vlan_data["restricted"] = False
            logger.info(f"VLAN {vlan_id} desrestringida")
        
        # Al detener: eliminar reglas iptables pero PRESERVAR la configuración en JSON
        # Esto permite que al reiniciar se respete la configuración del usuario
        # VLAN 1 se mantiene aislada por política fija; el resto se marca como no aislada
    
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
    
    # Limpiar y eliminar cadena SECURITY_DROPS_FIREWALL
    logger.info("Limpiando cadena SECURITY_DROPS_FIREWALL...")
    
    # Desvincular SECURITY_DROPS_FIREWALL de FORWARD
    for attempt in range(5):
        success, _ = _run_command([
            "iptables", "-D", "FORWARD", "-j", "SECURITY_DROPS_FIREWALL"
        ])
        if not success:
            break  # No hay más reglas de salto
        logger.info(f"Regla FORWARD → SECURITY_DROPS_FIREWALL eliminada (intento {attempt + 1})")
    
    # Limpiar todas las reglas de SECURITY_DROPS_FIREWALL
    success, _ = _run_command(["iptables", "-F", "SECURITY_DROPS_FIREWALL"])
    if success:
        logger.info("Cadena SECURITY_DROPS_FIREWALL limpiada")
    
    # Eliminar cadena SECURITY_DROPS_FIREWALL
    success, _ = _run_command(["iptables", "-X", "SECURITY_DROPS_FIREWALL"])
    if success:
        logger.info("Cadena SECURITY_DROPS_FIREWALL eliminada")
        results.append("Cadena SECURITY_DROPS_FIREWALL eliminada")
    
    # Limpiar y eliminar cadena INPUT_PROTECTION
    logger.info("Limpiando cadena INPUT_PROTECTION...")
    
    # Desvincular INPUT_PROTECTION de INPUT
    for attempt in range(5):
        success, _ = _run_command([
            "iptables", "-D", "INPUT", "-j", "INPUT_PROTECTION"
        ])
        if not success:
            break
        logger.info(f"Regla INPUT → INPUT_PROTECTION eliminada (intento {attempt + 1})")
    
    # Limpiar todas las reglas de INPUT_PROTECTION
    success, _ = _run_command(["iptables", "-F", "INPUT_PROTECTION"])
    if success:
        logger.info("Cadena INPUT_PROTECTION limpiada")
    
    # Eliminar cadena INPUT_PROTECTION
    success, _ = _run_command(["iptables", "-X", "INPUT_PROTECTION"])
    if success:
        logger.info("Cadena INPUT_PROTECTION eliminada")
        results.append("Cadena INPUT_PROTECTION eliminada")
    
    # Limpiar y eliminar cadena INPUT_RESTRICTIONS
    logger.info("Limpiando cadena INPUT_RESTRICTIONS...")
    
    # Desvincular INPUT_RESTRICTIONS de INPUT
    for attempt in range(5):
        success, _ = _run_command([
            "iptables", "-D", "INPUT", "-j", "INPUT_RESTRICTIONS"
        ])
        if not success:
            break
        logger.info(f"Regla INPUT → INPUT_RESTRICTIONS eliminada (intento {attempt + 1})")
    
    # Limpiar todas las reglas de INPUT_RESTRICTIONS
    success, _ = _run_command(["iptables", "-F", "INPUT_RESTRICTIONS"])
    if success:
        logger.info("Cadena INPUT_RESTRICTIONS limpiada")
    
    # Eliminar cadena INPUT_RESTRICTIONS
    success, _ = _run_command(["iptables", "-X", "INPUT_RESTRICTIONS"])
    if success:
        logger.info("Cadena INPUT_RESTRICTIONS eliminada")
        results.append("Cadena INPUT_RESTRICTIONS eliminada")
    
    fw_cfg["status"] = 0
    _save_firewall_config(fw_cfg)
    
    msg = "Firewall detenido:\n" + "\n".join(results)
    logger.info("=== FIN: firewall stop ===")
    
    # Registrar acción en actions.log
    log_action("firewall", msg)
    
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
    
    # Nota: stop() y start() ya registran en actions.log. Evitamos duplicar entradas aquí.
    return start_success, msg


def status(params: Dict[str, Any] = None) -> Tuple[bool, str]:
    """Obtener estado del firewall."""
    logger.info("=== INICIO: firewall status ===")
    
    # Ejecutar iptables -nvL y guardar en actions.log
    from datetime import datetime
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_file = os.path.join(BASE_DIR, "logs", "firewall", "actions.log")
    
    success, iptables_output = _run_command(["/usr/sbin/iptables", "-nvL"])
    if success:
        try:
            with open(log_file, "a") as f:
                f.write(f"\n\n{'=' * 80}\n")
                f.write(f"📋 FIREWALL STATUS - iptables -nvL\n")
                f.write(f"🕒 {timestamp}\n")
                f.write(f"{'=' * 80}\n\n")
                f.write(iptables_output)
                f.write(f"\n{'=' * 80}\n")
            logger.info(f"Estado de iptables guardado en {log_file}")
        except Exception as e:
            logger.error(f"Error guardando log: {e}")
    
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
    
    result_msg = f"Whitelist habilitada en VLAN {vlan_id}\n{msg}"
    logger.info(f"=== FIN: enable_whitelist - Success: {success} ===")
    
    # Registrar acción en actions.log
    if success:
        log_action("firewall", result_msg)
    
    return success, result_msg


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
    
    result_msg = f"Whitelist deshabilitada en VLAN {vlan_id}\n{msg}"
    logger.info(f"=== FIN: disable_whitelist - Success: {success} ===")
    
    # Registrar acción en actions.log
    if success:
        log_action("firewall", result_msg)
    
    return success, result_msg


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
    
    # Crear directorio de logs
    create_module_log_directory("firewall")
    
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
    
    # PROTECCIÓN: VLAN 1 no puede ser aislada manualmente
    if vlan_id == 1:
        logger.warning("Intento de aislar VLAN 1 manualmente bloqueado")
        return False, "VLAN 1 no puede ser aislada manualmente. Solo se aísla automáticamente al iniciar el firewall."
    
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
        
        # Asegurar que existe la cadena de seguridad
        _ensure_security_chain()
        
        # Verificar si ya está aislada (usando -d)
        success, output = _run_command([
            "iptables", "-C", "SECURITY_DROPS_FIREWALL", "-d", ip_mask, "-m", "conntrack", 
            "--ctstate", "NEW", "-j", "DROP"
        ])
        
        if success:
            logger.info(f"VLAN 1 ya está aislada")
            return True, f"VLAN 1 ya estaba aislada"
        
        # Añadir regla de aislamiento en SECURITY_DROPS_FIREWALL con -d (destination)
        # No añadimos a INPUT directamente para evitar conflicto con INPUT_RESTRICTIONS
        success, output = _run_command([
            "iptables", "-I", "SECURITY_DROPS_FIREWALL", "1", "-d", ip_mask, "-m", "conntrack", 
            "--ctstate", "NEW", "-j", "DROP"
        ])
        
        if not success:
            logger.error(f"Error aislando VLAN 1 en SECURITY_DROPS_FIREWALL: {output}")
            return False, f"Error al aislar VLAN 1: {output}"
        
        logger.info("Regla de aislamiento VLAN 1 añadida solo en SECURITY_DROPS_FIREWALL")
        
        msg = "VLAN 1 aislada correctamente. Tráfico entrante bloqueado (saliente permitido)."
    
    else:
        # VLANs normales: bloquear tráfico saliente (-s)
        logger.info(f"Aislando VLAN {vlan_id} con IP {ip_mask} (bloqueando tráfico saliente -s)")
        
        # Asegurar que existe la cadena de seguridad
        _ensure_security_chain()
        
        # Verificar si ya está aislada
        success, output = _run_command([
            "iptables", "-C", "SECURITY_DROPS_FIREWALL", "-s", ip_mask, "-m", "conntrack", 
            "--ctstate", "NEW", "-j", "DROP"
        ])
        
        if success:
            logger.info(f"VLAN {vlan_id} ya está aislada")
            return True, f"VLAN {vlan_id} ya estaba aislada"
        
        # Añadir regla de aislamiento en SECURITY_DROPS_FIREWALL con -s (source)
        # No añadimos a INPUT directamente para mantener separación de responsabilidades
        success, output = _run_command([
            "iptables", "-I", "SECURITY_DROPS_FIREWALL", "1", "-s", ip_mask, "-m", "conntrack", 
            "--ctstate", "NEW", "-j", "DROP"
        ])
        
        if not success:
            logger.error(f"Error aislando VLAN {vlan_id} en SECURITY_DROPS_FIREWALL: {output}")
            return False, f"Error al aislar VLAN {vlan_id}: {output}"
        
        logger.info(f"Regla de aislamiento VLAN {vlan_id} añadida en SECURITY_DROPS_FIREWALL")
        
        msg = f"VLAN {vlan_id} aislada correctamente. Las conexiones nuevas están bloqueadas."
    
    # Actualizar configuración
    vlan_cfg["isolated"] = True
    _save_firewall_config(fw_cfg)
    
    logger.info(f"VLAN {vlan_id} aislada exitosamente")
    logger.info("=== FIN: aislar ===")
    
    # Registrar acción en actions.log
    log_action("firewall", msg)
    
    return True, msg


def desaislar(params: Dict[str, Any] = None) -> Tuple[bool, str]:
    """Desaislar una VLAN eliminando el bloqueo de nuevas conexiones.
    Ahora también permite desaislar VLAN 1 (el usuario puede controlarlo manualmente).
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
    
    # PROTECCIÓN: VLAN 1 no puede ser desaislada manualmente
    if vlan_id == 1:
        logger.warning("Intento de desaislar VLAN 1 bloqueado")
        return False, "VLAN 1 no puede ser desaislada. Permanece aislada mientras el firewall esté activo."
    
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
        "iptables", "-C", "SECURITY_DROPS_FIREWALL", "-s", ip_mask, "-m", "conntrack", 
        "--ctstate", "NEW", "-j", "DROP"
    ])
    
    if not success:
        logger.info(f"VLAN {vlan_id} no estaba aislada")
        # Actualizar configuración por si acaso
        vlan_cfg["isolated"] = False
        _save_firewall_config(fw_cfg)
        return True, f"VLAN {vlan_id} no estaba aislada"
    
    # Eliminar regla de aislamiento de SECURITY_DROPS_FIREWALL
    success, output = _run_command([
        "iptables", "-D", "SECURITY_DROPS_FIREWALL", "-s", ip_mask, "-m", "conntrack", 
        "--ctstate", "NEW", "-j", "DROP"
    ])
    
    if not success:
        logger.error(f"Error desaislando VLAN {vlan_id} en SECURITY_DROPS_FIREWALL: {output}")
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
    
    msg = f"VLAN {vlan_id} desaislada correctamente. El tráfico ha sido restaurado."
    logger.info(f"VLAN {vlan_id} desaislada exitosamente")
    logger.info("=== FIN: desaislar ===")
    
    # Registrar acción en actions.log
    log_action("firewall", msg)
    
    return True, msg


# -----------------------------
def restrict(params: Dict[str, Any] = None) -> Tuple[bool, str]:
    """Restringir una VLAN bloqueando acceso al router (INPUT) según ID.
    Usa cadena INPUT_RESTRICTIONS para garantizar evaluación controlada.
    VLAN 1 y 2: DROP todo
    Otras VLANs: permitir solo DHCP (67/68), DNS (53 TCP/UDP) e ICMP, DROPar el resto
    """
    logger.info("=== INICIO: restrict ===")
    
    # Validar parámetros
    if not params or "vlan_id" not in params:
        return False, "Error: vlan_id requerido"

    suppress_log = bool(params.get("suppress_log", False))
    
    try:
        vlan_id = int(params["vlan_id"])
    except (ValueError, TypeError):
        return False, f"Error: vlan_id debe ser entero"
    
    if vlan_id < 1 or vlan_id > 4094:
        return False, f"Error: vlan_id inválido"
    
    fw_cfg = _load_firewall_config()
    
    if str(vlan_id) not in fw_cfg.get("vlans", {}):
        return False, f"Error: VLAN {vlan_id} no está configurada"
    
    vlan_cfg = fw_cfg["vlans"][str(vlan_id)]
    vlan_ip_network = vlan_cfg.get("ip", "")
    
    if not vlan_ip_network:
        return False, f"Error: VLAN {vlan_id} no tiene IP configurada"
    
    # Calcular máscara si no está
    if '/' not in vlan_ip_network:
        ip_mask = f"{vlan_ip_network}/24"
    else:
        ip_mask = vlan_ip_network
    
    logger.info(f"Aplicando restricciones a VLAN {vlan_id} ({ip_mask})")
    
    # Verificar si ya está restringida
    if vlan_cfg.get("restricted", False):
        return True, f"VLAN {vlan_id} ya estaba restringida"
    
    # Asegurar que la cadena INPUT_RESTRICTIONS existe y está bien posicionada
    _ensure_input_restriction_chain()
    
    # Determinar restricción según VLAN
    if vlan_id in [1, 2]:
        # VLAN 1 y 2: DROP todo desde esa VLAN
        logger.info(f"VLAN {vlan_id}: aplicando DROP total")
        
        # Verificar si la regla ya existe
        check_exists = _run_command([
            "iptables", "-C", "INPUT_RESTRICTIONS", "-s", ip_mask, "-j", "DROP"
        ])[0]
        
        if check_exists:
            logger.info(f"Regla DROP para VLAN {vlan_id} ya existe en INPUT_RESTRICTIONS")
            msg = f"VLAN {vlan_id} restringida: bloqueado acceso total al router"
        else:
            success, output = _run_command([
                "iptables", "-A", "INPUT_RESTRICTIONS", "-s", ip_mask, "-j", "DROP"
            ])
            
            if not success:
                logger.error(f"Error aplicando restricción a VLAN {vlan_id}: {output}")
                return False, f"Error al restringir VLAN {vlan_id}: {output}"
            
            msg = f"VLAN {vlan_id} restringida: bloqueado acceso total al router"
    
    else:
        # Otras VLANs: permitir DHCP, DNS e ICMP; bloquear el resto
        logger.info(f"VLAN {vlan_id}: permitiendo DHCP, DNS e ICMP; bloqueando resto")
        
        # DHCP (puertos 67/68 UDP) - verificar antes de añadir
        if not _run_command(["iptables", "-C", "INPUT_RESTRICTIONS", "-s", ip_mask, "-p", "udp", "--dport", "67:68", "-j", "ACCEPT"])[0]:
            success_dhcp = _run_command([
                "iptables", "-A", "INPUT_RESTRICTIONS", "-s", ip_mask, "-p", "udp", "--dport", "67:68", "-j", "ACCEPT"
            ])[0]
            if not success_dhcp:
                logger.warning(f"Error permitiendo DHCP para VLAN {vlan_id}")
            else:
                logger.info(f"Permitido DHCP desde VLAN {vlan_id}")
        
        # DNS UDP 53 - verificar antes de añadir
        if not _run_command(["iptables", "-C", "INPUT_RESTRICTIONS", "-s", ip_mask, "-p", "udp", "--dport", "53", "-j", "ACCEPT"])[0]:
            _run_command([
                "iptables", "-A", "INPUT_RESTRICTIONS", "-s", ip_mask, "-p", "udp", "--dport", "53", "-j", "ACCEPT"
            ])
        
        # DNS TCP 53 - verificar antes de añadir
        if not _run_command(["iptables", "-C", "INPUT_RESTRICTIONS", "-s", ip_mask, "-p", "tcp", "--dport", "53", "-j", "ACCEPT"])[0]:
            _run_command([
                "iptables", "-A", "INPUT_RESTRICTIONS", "-s", ip_mask, "-p", "tcp", "--dport", "53", "-j", "ACCEPT"
            ])
        
        # ICMP (ping) - verificar antes de añadir
        if not _run_command(["iptables", "-C", "INPUT_RESTRICTIONS", "-s", ip_mask, "-p", "icmp", "-j", "ACCEPT"])[0]:
            success_icmp = _run_command([
                "iptables", "-A", "INPUT_RESTRICTIONS", "-s", ip_mask, "-p", "icmp", "-j", "ACCEPT"
            ])[0]
            if not success_icmp:
                logger.warning(f"Error permitiendo ICMP para VLAN {vlan_id}")
            else:
                logger.info(f"Permitido ICMP desde VLAN {vlan_id}")
        
        # DROP todo lo demás - verificar antes de añadir
        check_drop = _run_command(["iptables", "-C", "INPUT_RESTRICTIONS", "-s", ip_mask, "-j", "DROP"])[0]
        if not check_drop:
            success, output = _run_command([
                "iptables", "-A", "INPUT_RESTRICTIONS", "-s", ip_mask, "-j", "DROP"
            ])
            
            if not success:
                logger.error(f"Error aplicando restricción a VLAN {vlan_id}: {output}")
                return False, f"Error al restringir VLAN {vlan_id}: {output}"
        
        msg = f"VLAN {vlan_id} restringida: solo DHCP, DNS e ICMP permitidos al router"
    
    # Marcar como restringida en configuración
    vlan_cfg["restricted"] = True
    _save_firewall_config(fw_cfg)
    
    logger.info(f"=== FIN: restrict - VLAN {vlan_id} restringida ===")
    if not suppress_log:
        log_action("firewall", msg)
    
    return True, msg


# -----------------------------
def unrestrict(params: Dict[str, Any] = None) -> Tuple[bool, str]:
    """Eliminar restricciones de una VLAN (INPUT) desde cadena INPUT_RESTRICTIONS."""
    logger.info("=== INICIO: unrestrict ===")
    
    # Validar parámetros
    if not params or "vlan_id" not in params:
        return False, "Error: vlan_id requerido"
    
    try:
        vlan_id = int(params["vlan_id"])
    except (ValueError, TypeError):
        return False, f"Error: vlan_id debe ser entero"
    
    if vlan_id < 1 or vlan_id > 4094:
        return False, f"Error: vlan_id inválido"
    
    fw_cfg = _load_firewall_config()
    
    if str(vlan_id) not in fw_cfg.get("vlans", {}):
        return False, f"Error: VLAN {vlan_id} no está configurada"
    
    vlan_cfg = fw_cfg["vlans"][str(vlan_id)]
    vlan_ip_network = vlan_cfg.get("ip", "")
    
    if not vlan_ip_network:
        return False, f"Error: VLAN {vlan_id} no tiene IP configurada"
    
    # Calcular máscara si no está
    if '/' not in vlan_ip_network:
        ip_mask = f"{vlan_ip_network}/24"
    else:
        ip_mask = vlan_ip_network
    
    logger.info(f"Eliminando restricciones de VLAN {vlan_id} ({ip_mask})")
    
    # Verificar si estaba restringida
    if not vlan_cfg.get("restricted", False):
        logger.info(f"VLAN {vlan_id} no estaba restringida")
        return True, f"VLAN {vlan_id} no estaba restringida"
    
    # Eliminar reglas desde INPUT_RESTRICTIONS según VLAN
    if vlan_id in [1, 2]:
        # Solo hay una regla DROP
        _run_command([
            "iptables", "-D", "INPUT_RESTRICTIONS", "-s", ip_mask, "-j", "DROP"
        ])
    else:
        # Eliminar reglas: DHCP, DNS (UDP/TCP), ICMP y DROP
        _run_command([
            "iptables", "-D", "INPUT_RESTRICTIONS", "-s", ip_mask, "-p", "udp", "--dport", "67:68", "-j", "ACCEPT"
        ])
        _run_command([
            "iptables", "-D", "INPUT_RESTRICTIONS", "-s", ip_mask, "-p", "udp", "--dport", "53", "-j", "ACCEPT"
        ])
        _run_command([
            "iptables", "-D", "INPUT_RESTRICTIONS", "-s", ip_mask, "-p", "tcp", "--dport", "53", "-j", "ACCEPT"
        ])
        _run_command([
            "iptables", "-D", "INPUT_RESTRICTIONS", "-s", ip_mask, "-p", "icmp", "-j", "ACCEPT"
        ])
        _run_command([
            "iptables", "-D", "INPUT_RESTRICTIONS", "-s", ip_mask, "-j", "DROP"
        ])
    
    # Marcar como no restringida
    vlan_cfg["restricted"] = False
    _save_firewall_config(fw_cfg)
    
    msg = f"VLAN {vlan_id} desrestringida"
    logger.info(f"=== FIN: unrestrict - {msg} ===")
    log_action("firewall", msg)
    
    return True, msg


# -----------------------------
def reset_defaults(params: Dict[str, Any] = None) -> Tuple[bool, str]:
    """Restaurar configuración de firewall a valores seguros por defecto.
    VLAN 1: isolated=true, restricted=false
    Otras VLANs: restricted=true
    Aplica cambios y reinicia el firewall.
    """
    logger.info("=== INICIO: reset_defaults ===")
    
    fw_cfg = _load_firewall_config()
    changes = []
    
    # Restablecer VLAN 1: aislada pero no restringida
    if "1" in fw_cfg.get("vlans", {}):
        vlan1_cfg = fw_cfg["vlans"]["1"]
        vlan1_cfg["isolated"] = True
        vlan1_cfg["restricted"] = False
        changes.append("VLAN 1: isolated=true, restricted=false")
        logger.info("VLAN 1 configurada: aislada")
    
    # Restablecer otras VLANs: restringidas
    for vlan_id, vlan_cfg in fw_cfg.get("vlans", {}).items():
        if vlan_id != "1":
            vlan_cfg["restricted"] = True
            changes.append(f"VLAN {vlan_id}: restricted=true")
            logger.info(f"VLAN {vlan_id} configurada: restringida")
    
    # Guardar configuración
    _save_firewall_config(fw_cfg)
    
    # Reiniciar firewall para aplicar cambios
    logger.info("Reiniciando firewall para aplicar defaults...")
    stop_success, stop_msg = stop()
    if not stop_success:
        logger.warning(f"Advertencia al detener firewall: {stop_msg}")
    
    start_success, start_msg = start()
    if not start_success:
        msg = f"Error reiniciando firewall en reset_defaults: {start_msg}"
        logger.error(msg)
        return False, msg
    
    result_msg = "Firewall restaurado a valores por defecto:\n" + "\n".join(changes) + "\n\nFirewall reiniciado"
    logger.info(f"=== FIN: reset_defaults - {result_msg} ===")
    log_action("firewall", result_msg)
    
    return True, result_msg


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
    "restrict": restrict,
    "unrestrict": unrestrict,
    "reset_defaults": reset_defaults,
}