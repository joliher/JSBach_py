# app/core/expect.py
"""Módulo Expect para configuración de switches remotos."""

import os
import json
import tempfile
import subprocess
import re
from typing import Dict, Any, Tuple, List, Optional
from ..utils.helpers import (
    load_json_config, save_json_config, update_module_status,
    run_command, ensure_module_dirs, get_module_logger
)
from .helpers.helper_expect import (
    check_ip_reachability, validate_port_range, parse_config_blocks,
    validate_vlan_string, sanitize_config_value, load_profile,
    get_secrets, parse_ports
)
from ..utils.validators import validate_ip_address

# Config files
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
CONFIG_DIR = os.path.join(BASE_DIR, "config", "expect")
EXPECT_JSON = os.path.join(CONFIG_DIR, "expect.json")
SECRETS_JSON = os.path.join(CONFIG_DIR, "secrets.json")
PROFILES_DIR = os.path.join(CONFIG_DIR, "profiles")
LOG_DIR = os.path.join(BASE_DIR, "logs", "expect")

logger = get_module_logger("expect")


def config(params: Dict[str, Any]) -> Tuple[bool, str]:
    """Configura un switch remoto."""
    ensure_module_dirs(BASE_DIR, "expect")
    
    ip = params.get("ip")
    profile_id = params.get("profile", "cisco_ios")
    actions_str = params.get("actions", "")
    dry_run = params.get("dry_run", False)

    # Seguridad: Validar profile_id para evitar path traversal
    if profile_id and not re.match(r"^[a-zA-Z0-9_-]+$", profile_id):
        return False, "Identificador de perfil inválido."
    
    if not ip or not actions_str:
        return False, "Faltan parámetros obligatorios: ip, actions"
    
    # 1. Cargar Perfil
    profile = load_profile(profile_id, PROFILES_DIR)
    if not profile:
        return False, f"Perfil '{profile_id}' no encontrado"

    # 2. Reachability (solo si no es dry_run)
    if not dry_run and not check_ip_reachability(ip):
        return False, f"La IP {ip} no es alcanzable (ping fallido)"
    
    # 3. Validar Autenticación
    # Override de perfil si se proporciona en params
    auth_required = params.get("auth_required")
    if auth_required is None:
        auth_required = profile.get("auth_required", True)
    
    user, password = get_secrets(ip, SECRETS_JSON)
    if auth_required and not user:
        return False, f"Autenticación requerida para {ip}. Configure con 'expect auth'"
    
    # 4. Parsear y Validar Acciones
    blocks = parse_config_blocks(actions_str)
    if not blocks:
        return False, "No se definieron acciones válidas"
    
    used_global_params = set()
    validated_blocks = []
    
    for block in blocks:
        ports_str = block.pop("ports", None)
        port_list = []
        if ports_str:
            valid, ports, err = validate_port_range(ports_str, profile.get("max_ports", 24))
            if not valid:
                return False, f"Error en puertos: {err}"
            port_list = ports
        
        # Validar parámetros del bloque y detectar duplicados
        if 'tag' in block and 'untag' in block:
            return False, "Un puerto no puede estar en TAG y UNTAG a la vez en el mismo bloque."

        block_keys = set()
        for key, val in block.items():
            if key in block_keys:
                return False, f"Parámetro duplicado detectado en el mismo bloque: '{key}'"
            block_keys.add(key)

            param_def = profile.get("parameters", {}).get(key)
            if not param_def:
                return False, f"Parámetro '{key}' no soportado por el perfil {profile_id}"
            
            # Validar contexto
            expected_context = "interface" if port_list else "global"
            if param_def.get("context") != expected_context:
                return False, f"Parámetro '{key}' debe usarse en contexto {param_def.get('context')}, no en {expected_context}"
            
            # Si es un parámetro global, asegurar que no se repite en otros bloques
            if expected_context == "global":
                if key in used_global_params:
                    return False, f"El parámetro global '{key}' no puede definirse más de una vez."
                used_global_params.add(key)
            
            # Sanitización de valor
            sanitized_val = sanitize_config_value(val)
            
            # 1. Dependencia Secuencial: VLAN, TAG y UNTAG requieren MODE en interfaz
            if key in ["vlan", "tag", "untag"]:
                mode = block.get("mode")
                if not mode:
                    return False, f"El parámetro '{key}' requiere que se haya definido el parámetro 'mode' en el mismo bloque."
                
                if key == "vlan" and mode != "access":
                    return False, f"El parámetro 'vlan' solo es válido en modo 'access'. El modo actual es '{mode}'."
                
                if profile_id == "cisco_ios":
                    # En Cisco:
                    # - 'vlan' va con mode:access (ya validado arriba)
                    # - 'tag' va con mode:trunk
                    if key != "vlan" and mode != "trunk":
                        return False, f"En Cisco, '{key}' requiere mode:trunk"
                    if key == "untag":
                        return False, "En el perfil Cisco, no se permite el uso de 'untag' en modo trunk. Use 'vlan' para configurar puertos de acceso."
                elif profile_id == "tp_link":
                    if mode != "general":
                        return False, f"En TP-Link, '{key}' requiere mode:general"

            # 3. Validación de Tipo y Sanitización Final
            if key in ["vlan", "tag", "untag"]:
                ok, clean_val, err = validate_vlan_string(sanitized_val)
                if not ok:
                    return False, f"Error en parámetro '{key}': {err}"
                block[key] = clean_val
            else:
                block[key] = sanitized_val
        
        # 4. REQUISITO: Si mode es 'general', DEBE haber al menos un 'tag' o 'untag'
        if block.get("mode") == "general":
            if not block.get("tag") and not block.get("untag"):
                return False, f"El modo 'general' requiere que se especifique al menos un parámetro 'tag' o 'untag' en el bloque de puertos {port_list}."

        validated_blocks.append({"ports": port_list, "actions": block})
    
    # Validar IP de destino principal
    ip_valid, ip_err = validate_ip_address(ip)
    if not ip_valid:
        return False, f"IP de destino inválida: {ip_err}"

    # 5. Generar Script Expect
    script_lines = []
    
    auth_type = profile.get('auth_type', 'nc')
    if auth_type == "nc":
        script_lines.append(f"spawn nc {ip} 23")
    else:
        script_lines.append(f"spawn {auth_type} {ip}")
    
    # Configuración de timeout y comportamiento
    script_lines.append("set timeout 30")
    
    if auth_required and user:
        script_lines.append(f"expect \"{profile['prompts']['login']}\"")
        script_lines.append(f"send \"{user}\\r\"")
        script_lines.append(f"expect \"{profile['prompts']['password']}\"")
        script_lines.append(f"send \"{password}\\r\"")
    
    script_lines.append(f"expect \"{profile['prompts']['exec']}\"")
    script_lines.append("after 200")
    script_lines.append(f"send \"configure terminal\\r\"")
    
    for block in validated_blocks:
        if not block["ports"]:
            # Contexto Global
            for key, val in block["actions"].items():
                cmd_tmpl = profile["parameters"][key]["cmd"]
                script_lines.append(f"expect \"{profile['prompts']['config']}\"")
                script_lines.append("after 100")
                script_lines.append(f"send \"{cmd_tmpl.format(value=sanitize_config_value(val))}\\r\"")
        else:
            # Contexto Interfaz
            port_prefix = profile.get("port_prefix", "ethernet ")
            for port in block["ports"]:
                script_lines.append(f"expect \"{profile['prompts']['config']}\"")
                script_lines.append("after 100")
                script_lines.append(f"send \"interface {port_prefix}{port}\\r\"")
                for key, val in block["actions"].items():
                    cmd_tmpl = profile["parameters"][key]["cmd"]
                    script_lines.append(f"expect \"{profile['prompts']['interface']}\"")
                    script_lines.append("after 100")
                    script_lines.append(f"send \"{cmd_tmpl.format(value=val)}\\r\"")
                script_lines.append(f"expect \"{profile['prompts']['interface']}\"")
                script_lines.append("after 100")
                script_lines.append(f"send \"exit\\r\"")
    
    script_lines.append(f"expect \"{profile['prompts']['config']}\"")
    script_lines.append("after 100")
    script_lines.append(f"send \"exit\\r\"")
    script_lines.append(f"expect \"{profile['prompts']['exec']}\"")
    script_lines.append("after 100")
    script_lines.append(f"send \"write memory\\r\"")
    script_lines.append("expect eof")
    
    full_script = "\n".join(script_lines)
    
    if dry_run:
        return True, f"MODO SIMULACIÓN (Script generado):\n\n{full_script}"
    
    # 6. Ejecutar Script
    with tempfile.NamedTemporaryFile(mode='w', suffix='.exp', delete=False) as f:
        f.write(full_script)
        script_path = f.name
    
    try:
        logger.info(f"Ejecutando configuración en {ip} (Perfil: {profile_id})")
        result = subprocess.run(["expect", script_path], capture_output=True, text=True, timeout=60)
        if os.path.exists(script_path): os.remove(script_path)
        
        if result.returncode == 0:
            logger.info(f"Configuración completada exitosamente en {ip}")
            return True, f"Configuración aplicada en {ip}:\n{result.stdout}"
        else:
            logger.error(f"Error ejecutando expect en {ip}: {result.stderr}")
            
            # Sanitizar errores críticos para el usuario
            combined_msg = (result.stdout + " " + result.stderr).lower()
            
            if "connection refused" in combined_msg or "conexión rehusada" in combined_msg:
                return False, "Error: No se pudo establecer conexión con el equipo (Host inalcanzable o puerto cerrado)."
            
            if "connection timed out" in combined_msg or "tiempo de espera agotado" in combined_msg:
                return False, "Error: Tiempo de espera agotado al conectar con el equipo."
            
            if "connection closed" in combined_msg or "conexión cerrada" in combined_msg:
                return False, "Error: La conexión fue cerrada por el equipo remoto inesperadamente."
            
            if "spawn id" in combined_msg and "not open" in combined_msg:
                return False, "Error: La sesión interactiva se interrumpió durante la configuración."
                
            return False, "Error: Fallo crítico en la comunicación con el dispositivo (Conexión interrumpida)."
            
    except subprocess.TimeoutExpired:
        if os.path.exists(script_path): os.remove(script_path)
        return False, "Timeout: El switch no respondió a tiempo"
    except Exception as e:
        if os.path.exists(script_path): os.remove(script_path)
        logger.exception(f"Error interno en orquestación: {str(e)}")
        return False, "Error interno del sistema al procesar la orquestación."

def auth(params: Dict[str, Any]) -> Tuple[bool, str]:
    """Gestiona credenciales."""
    ip = params.get("ip")
    user = params.get("user")
    password = params.get("password")
    
    if not ip or not user or not password:
        return False, "Faltan parámetros: ip, user, password"
    
    try:
        secrets = {}
        if os.path.exists(SECRETS_JSON):
            with open(SECRETS_JSON, 'r') as f:
                secrets = json.load(f)
        
        secrets[ip] = {"user": user, "password": password}
        
        with open(SECRETS_JSON, 'w') as f:
            json.dump(secrets, f, indent=4)
        
        try:
            os.chmod(SECRETS_JSON, 0o660)
        except PermissionError:
            pass # No somos dueños, pero ya escribimos el contenido
        
        return True, f"Credenciales guardadas para {ip}"
    except Exception as e:
        return False, f"Error guardando credenciales: {e}"

def reset(params: Dict[str, Any]) -> Tuple[bool, str]:
    """Resetea (Soft Reset) todos los puertos a su estado por defecto."""
    ip = params.get("ip")
    profile_id = params.get("profile", "cisco_ios")
    dry_run = params.get("dry_run", False)
    
    if not ip:
        return False, "Falta parámetro obligatorio: ip"
    
    # 1. Cargar datos del perfil
    profile = load_profile(profile_id, PROFILES_DIR)
    if not profile:
        return False, f"Perfil '{profile_id}' no encontrado"
    
    reset_cmd_tmpl = profile.get("reset_cmd")
    if not reset_cmd_tmpl:
        return False, f"El perfil '{profile_id}' no soporta la función de reset."
    
    max_ports = profile.get("max_ports", 24)
    auth_required = profile.get("auth_required", True)
    
    # 2. Reachability y Credenciales
    if not dry_run and not check_ip_reachability(ip):
        return False, f"La IP {ip} no es alcanzable"
        
    user, password = get_secrets(ip, SECRETS_JSON)
    if auth_required and not user:
        return False, f"Autenticación requerida para {ip}. Falta configurar credenciales (expect auth)."

    # 3. Generar Script de Reset Masivo
    script_lines = []
    auth_type = profile.get('auth_type', 'nc')
    
    # Conexión
    cmd_conn = f"spawn nc {ip} 23" if auth_type == "nc" else f"spawn {auth_type} {ip}"
    script_lines.append(cmd_conn)
    script_lines.append("set timeout 60") # Timeout extendido para operación masiva
    
    # Login
    if auth_required and user:
        script_lines.append(f"expect \"{profile['prompts']['login']}\"")
        script_lines.append(f"send \"{user}\\r\"")
        script_lines.append(f"expect \"{profile['prompts']['password']}\"")
        script_lines.append(f"send \"{password}\\r\"")
    
    script_lines.append(f"expect \"{profile['prompts']['exec']}\"")
    script_lines.append("after 200")
    script_lines.append(f"send \"configure terminal\\r\"")
    
    # Loop de puertos
    port_prefix = profile.get("port_prefix", "ethernet ")
    
    for i in range(1, max_ports + 1):
        script_lines.append(f"expect \"{profile['prompts']['config']}\"")
        script_lines.append("after 50")
        script_lines.append(f"send \"interface {port_prefix}{i}\\r\"")
        
        # Aplicar comandos de reset (soporta múltiples comandos separados por coma en TP-Link)
        cmds = reset_cmd_tmpl.replace("{port}", str(i)).split(',')
        for cmd in cmds:
            script_lines.append(f"expect \"{profile['prompts']['interface']}\"")
            script_lines.append("after 50")
            script_lines.append(f"send \"{cmd.strip()}\\r\"")
            
        script_lines.append(f"expect \"{profile['prompts']['interface']}\"")
        script_lines.append("after 50")
        script_lines.append(f"send \"exit\\r\"")

    # Guardar y Salir
    script_lines.append(f"expect \"{profile['prompts']['config']}\"")
    script_lines.append(f"send \"exit\\r\"")
    script_lines.append(f"expect \"{profile['prompts']['exec']}\"")
    script_lines.append(f"send \"write memory\\r\"")
    script_lines.append("expect eof")
    
    full_script = "\n".join(script_lines)
    
    if dry_run:
        return True, f"MODO SIMULACIÓN (Reset Masivo):\n\n{full_script}"
    
    # Ejecución Real (Reutilizando lógica)
    with tempfile.NamedTemporaryFile(mode='w', suffix='.exp', delete=False) as f:
        f.write(full_script)
        script_path = f.name
        
    try:
        logger.warning(f"EJECUTANDO SOFT RESET EN {ip} (Perfil: {profile_id})")
        result = subprocess.run(["expect", script_path], capture_output=True, text=True, timeout=120)
        if os.path.exists(script_path): os.remove(script_path)
        
        if result.returncode == 0:
            return True, f"Soft Reset completado en {ip}. Todos los puertos restablecidos."
        else:
            return False, f"Error en reset: {result.stderr}"
    except Exception as e:
        if os.path.exists(script_path): os.remove(script_path)
        logger.exception(f"Error crítico en reset: {e}")
        return False, "Fallo crítico al ejecutar el reset."


def port_security(params: Dict[str, Any]) -> Tuple[bool, str]:
    """Configura Port Security (Whitelist de MACs) en puertos específicos."""
    ip = params.get("ip")
    profile_id = params.get("profile", "cisco_ios")
    ports_str = str(params.get("ports", ""))
    macs_input = str(params.get("macs", ""))
    dry_run = params.get("dry_run", False)
    
    if not ip or not ports_str or not macs_input:
        return False, "Faltan parámetros obligatorios: ip, ports, macs"

    # 1. Validación Estricta
    try:
        ports = parse_ports(ports_str)
    except ValueError as e:
        return False, f"Error en puertos: {e}"
    except Exception:
        return False, "Formato de puertos inválido. Use formato compacto: 1,2-4 (sin espacios)."
        
    # Validar MACs (separadas por espacio o coma)
    macs = [m.strip() for m in macs_input.replace(',', ' ').split()]
    mac_regex = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$|^([0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}$")
    
    for mac in macs:
        if not mac_regex.match(mac):
            return False, f"Formato de MAC inválido: {mac}"

    # 2. Cargar Perfil
    profile = load_profile(profile_id, PROFILES_DIR)
    if not profile: return False, f"Perfil '{profile_id}' no encontrado"
    
    ps_cmds = profile.get("port_security_cmds")
    if not ps_cmds:
        return False, f"El perfil '{profile_id}' no soporta Port Security."

    auth_required = profile.get("auth_required", True)
    
    # 3. Preparar Conexión
    if not dry_run and not check_ip_reachability(ip):
        return False, f"La IP {ip} no es alcanzable"
        
    user, password = get_secrets(ip, SECRETS_JSON)
    if auth_required and not user:
        return False, f"Autenticación requerida para {ip}."

    # 4. Generar Script
    script_lines = []
    auth_type = profile.get('auth_type', 'nc')
    
    cmd_conn = f"spawn nc {ip} 23" if auth_type == "nc" else f"spawn {auth_type} {ip}"
    script_lines.append(cmd_conn)
    script_lines.append("set timeout 60")
    
    if auth_required and user:
        script_lines.append(f"expect \"{profile['prompts']['login']}\"")
        script_lines.append(f"send \"{user}\\r\"")
        script_lines.append(f"expect \"{profile['prompts']['password']}\"")
        script_lines.append(f"send \"{password}\\r\"")
        
    script_lines.append(f"expect \"{profile['prompts']['exec']}\"")
    script_lines.append("after 200")
    script_lines.append(f"send \"configure terminal\\r\"")
    
    port_prefix = profile.get("port_prefix", "ethernet ")
    
    for port in ports:
        script_lines.append(f"expect \"{profile['prompts']['config']}\"")
        script_lines.append("after 50")
        script_lines.append(f"send \"interface {port_prefix}{port}\\r\"")
        
        # Habilitar Port Security
        script_lines.append(f"expect \"{profile['prompts']['interface']}\"")
        script_lines.append(f"send \"{ps_cmds['enable']}\\r\"")
        
        # Configurar Máx MACs
        script_lines.append(f"expect \"{profile['prompts']['interface']}\"")
        cmds_max = ps_cmds['max'].replace("{value}", str(len(macs)))
        script_lines.append(f"send \"{cmds_max}\\r\"")
        
        # Configurar Violación (Restrict por defecto)
        script_lines.append(f"expect \"{profile['prompts']['interface']}\"")
        cmds_vio = ps_cmds['violation'].replace("{value}", "restrict")
        script_lines.append(f"send \"{cmds_vio}\\r\"")
        
        # Añadir MACs estáticas
        for mac in macs:
            script_lines.append(f"expect \"{profile['prompts']['interface']}\"")
            cmd_mac = ps_cmds['mac'].replace("{value}", mac)
            script_lines.append(f"send \"{cmd_mac}\\r\"")
            
        script_lines.append(f"expect \"{profile['prompts']['interface']}\"")
        script_lines.append(f"send \"exit\\r\"")

    # Guardar
    script_lines.append(f"expect \"{profile['prompts']['config']}\"")
    script_lines.append(f"send \"exit\\r\"")
    script_lines.append(f"expect \"{profile['prompts']['exec']}\"")
    script_lines.append(f"send \"write memory\\r\"")
    script_lines.append("expect eof")
    
    full_script = "\n".join(script_lines)
    
    if dry_run:
        return True, f"MODO SIMULACIÓN (Port Security):\n\n{full_script}"

    # Ejecución Real
    with tempfile.NamedTemporaryFile(mode='w', suffix='.exp', delete=False) as f:
        f.write(full_script)
        script_path = f.name
        
    try:
        logger.warning(f"APLICANDO PORT SECURITY EN {ip} Puertos:{ports} MACs:{len(macs)}")
        result = subprocess.run(["expect", script_path], capture_output=True, text=True, timeout=120)
        if os.path.exists(script_path): os.remove(script_path)
        
        if result.returncode == 0:
            return True, f"Port Security aplicado correctamente en puertos {ports}"
        else:
            return False, f"Error aplicando seguridad: {result.stderr}"
    except Exception as e:
        if os.path.exists(script_path): os.remove(script_path)
        logger.exception(f"Error crítico: {e}")
        return False, "Fallo crítico."

def status(params: Dict[str, Any] = None) -> Tuple[bool, str]: return True, "Módulo Expect activo"
def start(params: Dict[str, Any] = None) -> Tuple[bool, str]: return True, "Módulo Expect iniciado"
def stop(params: Dict[str, Any] = None) -> Tuple[bool, str]: return True, "Módulo Expect detenido"
def restart(params: Dict[str, Any] = None) -> Tuple[bool, str]: return True, "Módulo Expect reiniciado"

ALLOWED_ACTIONS = {
    "config": config,
    "auth": auth,
    "status": status,
    "reset": reset,
    "port-security": port_security,
    "start": start,
    "stop": stop,
    "restart": restart
}
