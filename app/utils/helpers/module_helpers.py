# app/core/module_helpers.py
"""
Funciones auxiliares comunes para todos los módulos core.
Centraliza: config I/O, status management, command execution, validación de interfaces.
"""

import subprocess
import json
import os
import fcntl
import re
import logging
from typing import Dict, Any, Tuple, Optional

# Configurar logging
logger = logging.getLogger(__name__)


# =============================================================================
# GESTIÓN DE CONFIGURACIÓN (Config I/O)
# =============================================================================

def load_json_config(file_path: str, default_value: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Cargar configuración JSON desde archivo.
    
    Args:
        file_path: Ruta al archivo JSON
        default_value: Valor por defecto si no existe o está vacío
    
    Returns:
        Dict con la configuración cargada
    """
    if default_value is None:
        default_value = {}
    
    if not os.path.exists(file_path):
        return default_value
    
    try:
        with open(file_path, "r") as f:
            content = f.read().strip()
            if not content:
                return default_value
            return json.loads(content)
    except (json.JSONDecodeError, Exception) as e:
        logger.error(f"Error cargando configuración de {file_path}: {e}")
        return default_value


def save_json_config(file_path: str, data: Dict[str, Any]) -> bool:
    """
    Guardar configuración JSON en archivo con lock exclusivo.
    
    Args:
        file_path: Ruta al archivo JSON
        data: Dict a guardar
    
    Returns:
        True si se guardó exitosamente, False en caso contrario
    """
    try:
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, "w") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            json.dump(data, f, indent=4)
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        logger.info(f"Configuración guardada en {file_path}")
        return True
    except Exception as e:
        logger.error(f"Error guardando configuración en {file_path}: {e}")
        return False


# =============================================================================
# GESTIÓN DE STATUS
# =============================================================================

def update_module_status(file_path: str, status: int) -> bool:
    """
    Actualizar el status de un módulo en su archivo de configuración.
    
    Args:
        file_path: Ruta al archivo de configuración JSON
        status: 0=inactivo, 1=activo
    
    Returns:
        True si se actualizó exitosamente
    """
    cfg = load_json_config(file_path, {})
    cfg["status"] = status
    return save_json_config(file_path, cfg)


def get_module_status(file_path: str) -> int:
    """
    Obtener el status actual de un módulo.
    
    Args:
        file_path: Ruta al archivo de configuración JSON
    
    Returns:
        0 si inactivo, 1 si activo, -1 si no existe
    """
    cfg = load_json_config(file_path, {})
    return cfg.get("status", -1)


# =============================================================================
# EJECUCIÓN DE COMANDOS
# =============================================================================

def run_command(cmd: list, use_sudo: bool = True, timeout: int = 30) -> Tuple[bool, str]:
    """
    Ejecutar comando shell con opciones de sudo y timeout.
    
    Args:
        cmd: Lista de componentes del comando
        use_sudo: Si True, antepone 'sudo'
        timeout: Timeout en segundos
    
    Returns:
        Tuple[success, output/error_message]
    """
    try:
        full_cmd = (["sudo"] + cmd) if use_sudo else cmd
        result = subprocess.run(
            full_cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False
        )
        
        if result.returncode == 0:
            return True, result.stdout.strip()
        else:
            error_msg = result.stderr.strip() or "Comando falló sin mensaje de error"
            return False, error_msg
    
    except subprocess.TimeoutExpired:
        return False, f"Timeout ejecutando comando (>{timeout}s)"
    except Exception as e:
        return False, f"Error ejecutando comando: {str(e)}"


# =============================================================================
# VALIDACIÓN DE INTERFACES
# =============================================================================

def validate_interface_name(name: str) -> bool:
    """
    Validar que el nombre de interfaz sea seguro.
    Solo permite: alfanuméricos, puntos, guiones, guiones bajos.
    
    Args:
        name: Nombre de la interfaz a validar
    
    Returns:
        True si es válido, False en caso contrario
    """
    if not name or not isinstance(name, str):
        return False
    return bool(re.match(r'^[a-zA-Z0-9._-]+$', name))


def interface_exists(iface_name: str) -> bool:
    """
    Verificar si una interfaz existe en el sistema.
    
    Args:
        iface_name: Nombre de la interfaz
    
    Returns:
        True si existe, False en caso contrario
    """
    success, output = run_command(["ip", "link", "show", iface_name], use_sudo=False)
    return success


# =============================================================================
# CARGAR CONFIGURACIÓN DE OTROS MÓDULOS
# =============================================================================

def load_module_config(base_dir: str, module_name: str, default: Dict = None) -> Dict[str, Any]:
    """
    Cargar configuración de otro módulo.
    
    Args:
        base_dir: Directorio base del proyecto
        module_name: Nombre del módulo (ej: "wan", "vlans", etc)
        default: Valor por defecto si no existe
    
    Returns:
        Dict con la configuración
    """
    if default is None:
        default = {}
    
    config_file = os.path.join(base_dir, "config", module_name, f"{module_name}.json")
    return load_json_config(config_file, default)


def get_wan_interface(base_dir: str) -> Optional[str]:
    """
    Obtener la interfaz WAN configurada.
    
    Args:
        base_dir: Directorio base del proyecto
    
    Returns:
        Nombre de la interfaz o None si no está configurada
    """
    wan_cfg = load_module_config(base_dir, "wan", {})
    return wan_cfg.get("interface")


# =============================================================================
# UTILIDADES PARA DIRECTORIOS
# =============================================================================

def ensure_module_dirs(base_dir: str, module_name: str) -> None:
    """
    Asegurar que existan los directorios de config y logs para un módulo.
    
    Args:
        base_dir: Directorio base del proyecto
        module_name: Nombre del módulo
    """
    config_dir = os.path.join(base_dir, "config", module_name)
    log_dir = os.path.join(base_dir, "logs", module_name)
    
    os.makedirs(config_dir, exist_ok=True)
    os.makedirs(log_dir, exist_ok=True)


def get_config_file_path(base_dir: str, module_name: str) -> str:
    """
    Obtener la ruta del archivo de configuración de un módulo.
    
    Args:
        base_dir: Directorio base del proyecto
        module_name: Nombre del módulo
    
    Returns:
        Ruta completa al archivo JSON de configuración
    """
    return os.path.join(base_dir, "config", module_name, f"{module_name}.json")


def get_log_file_path(base_dir: str, module_name: str) -> str:
    """
    Obtener la ruta del archivo de log de un módulo.
    
    Args:
        base_dir: Directorio base del proyecto
        module_name: Nombre del módulo
    
    Returns:
        Ruta completa al archivo de log
    """
    return os.path.join(base_dir, "logs", module_name, "actions.log")
