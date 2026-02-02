# app/core/io_helpers.py
"""
Funciones auxiliares para I/O de archivos, logs y manejo de archivos.
Centraliza escritura de logs, archivos de configuración, y gestión de directorios.
"""

import os
import logging
import json
from typing import Optional, List, Tuple


# =============================================================================
# LOGGING
# =============================================================================

def get_module_logger(module_name: str) -> logging.Logger:
    """
    Obtener o crear un logger para un módulo específico.
    
    Args:
        module_name: Nombre del módulo
    
    Returns:
        Logger configurado
    """
    logger = logging.getLogger(f"jsbach.{module_name}")
    logger.setLevel(logging.DEBUG)
    return logger


def write_log_file(file_path: str, message: str, append: bool = True) -> bool:
    """
    Escribir mensaje en archivo de log.
    
    Args:
        file_path: Ruta al archivo de log
        message: Mensaje a escribir
        append: True para append, False para sobrescribir
    
    Returns:
        True si se escribió exitosamente
    """
    try:
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        mode = "a" if append else "w"
        
        with open(file_path, mode) as f:
            if append:
                f.write(message + "\n")
            else:
                f.write(message)
        
        return True
    except Exception as e:
        logging.error(f"Error escribiendo log en {file_path}: {e}")
        return False


def clear_log_file(file_path: str) -> bool:
    """
    Limpiar contenido de archivo de log.
    
    Args:
        file_path: Ruta al archivo de log
    
    Returns:
        True si se limpió exitosamente
    """
    try:
        with open(file_path, "w") as f:
            pass
        return True
    except Exception as e:
        logging.error(f"Error limpiando log {file_path}: {e}")
        return False


def read_log_file(file_path: str, lines: Optional[int] = None) -> str:
    """
    Leer contenido de archivo de log.
    
    Args:
        file_path: Ruta al archivo de log
        lines: Si se especifica, retorna solo las últimas N líneas
    
    Returns:
        Contenido del archivo
    """
    if not os.path.exists(file_path):
        return "(log file not found)"
    
    try:
        with open(file_path, "r") as f:
            content = f.read()
        
        if lines is not None and lines > 0:
            log_lines = content.split("\n")
            return "\n".join(log_lines[-lines:])
        
        return content
    except Exception as e:
        return f"Error leyendo log: {e}"


# =============================================================================
# MANEJO DE DIRECTORIOS
# =============================================================================

def ensure_directory_exists(dir_path: str) -> bool:
    """
    Asegurar que un directorio existe, creándolo si es necesario.
    
    Args:
        dir_path: Ruta del directorio
    
    Returns:
        True si existe o fue creado exitosamente
    """
    try:
        os.makedirs(dir_path, exist_ok=True)
        return True
    except Exception as e:
        logging.error(f"Error creando directorio {dir_path}: {e}")
        return False


def ensure_file_exists(file_path: str, default_content: str = "") -> bool:
    """
    Asegurar que un archivo existe, creándolo si es necesario.
    
    Args:
        file_path: Ruta del archivo
        default_content: Contenido por defecto si se crea
    
    Returns:
        True si existe o fue creado
    """
    if os.path.exists(file_path):
        return True
    
    try:
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, "w") as f:
            f.write(default_content)
        return True
    except Exception as e:
        logging.error(f"Error creando archivo {file_path}: {e}")
        return False


def list_directory_files(dir_path: str, extension: Optional[str] = None) -> List[str]:
    """
    Listar archivos en un directorio.
    
    Args:
        dir_path: Ruta del directorio
        extension: Si se especifica, filtrar por extensión (ej: ".json")
    
    Returns:
        Lista de nombres de archivo
    """
    if not os.path.exists(dir_path) or not os.path.isdir(dir_path):
        return []
    
    try:
        files = os.listdir(dir_path)
        
        if extension:
            files = [f for f in files if f.endswith(extension)]
        
        return files
    except Exception as e:
        logging.error(f"Error listando directorio {dir_path}: {e}")
        return []


def remove_file(file_path: str) -> bool:
    """
    Eliminar un archivo.
    
    Args:
        file_path: Ruta del archivo
    
    Returns:
        True si se eliminó exitosamente
    """
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
        return True
    except Exception as e:
        logging.error(f"Error eliminando archivo {file_path}: {e}")
        return False


# =============================================================================
# MANEJO DE ARCHIVOS JSON
# =============================================================================

def write_json_file(file_path: str, data: dict, pretty: bool = True) -> bool:
    """
    Escribir datos en archivo JSON.
    
    Args:
        file_path: Ruta del archivo
        data: Datos a escribir (dict)
        pretty: Si True, formatea el JSON
    
    Returns:
        True si se escribió exitosamente
    """
    try:
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        
        with open(file_path, "w") as f:
            if pretty:
                json.dump(data, f, indent=4)
            else:
                json.dump(data, f)
        
        return True
    except Exception as e:
        logging.error(f"Error escribiendo JSON en {file_path}: {e}")
        return False


def read_json_file(file_path: str, default: Optional[dict] = None) -> dict:
    """
    Leer datos de archivo JSON.
    
    Args:
        file_path: Ruta del archivo
        default: Valor por defecto si no existe o hay error
    
    Returns:
        Dict con los datos
    """
    if default is None:
        default = {}
    
    if not os.path.exists(file_path):
        return default
    
    try:
        with open(file_path, "r") as f:
            content = f.read().strip()
            if not content:
                return default
            return json.loads(content)
    except json.JSONDecodeError as e:
        logging.error(f"Error decodificando JSON en {file_path}: {e}")
        return default
    except Exception as e:
        logging.error(f"Error leyendo JSON en {file_path}: {e}")
        return default


# =============================================================================
# OPERACIONES DE ARCHIVOS EN BATCH
# =============================================================================

def backup_file(file_path: str, suffix: str = ".bak") -> Tuple[bool, str]:
    """
    Crear backup de un archivo.
    
    Args:
        file_path: Ruta del archivo a respaldar
        suffix: Sufijo para el archivo backup
    
    Returns:
        Tuple[success, backup_path or error_message]
    """
    if not os.path.exists(file_path):
        return False, f"Archivo no existe: {file_path}"
    
    backup_path = file_path + suffix
    
    try:
        with open(file_path, "r") as src:
            with open(backup_path, "w") as dst:
                dst.write(src.read())
        return True, backup_path
    except Exception as e:
        return False, f"Error creando backup: {e}"


def restore_from_backup(backup_path: str, original_path: str) -> bool:
    """
    Restaurar archivo desde backup.
    
    Args:
        backup_path: Ruta del backup
        original_path: Ruta donde restaurar
    
    Returns:
        True si se restauró exitosamente
    """
    if not os.path.exists(backup_path):
        logging.error(f"Backup no existe: {backup_path}")
        return False
    
    try:
        with open(backup_path, "r") as src:
            with open(original_path, "w") as dst:
                dst.write(src.read())
        return True
    except Exception as e:
        logging.error(f"Error restaurando desde backup: {e}")
        return False


def cleanup_old_logs(log_dir: str, keep_files: int = 5) -> int:
    """
    Limpiar archivos de log antiguos, manteniendo solo los N más recientes.
    
    Args:
        log_dir: Directorio de logs
        keep_files: Número de archivos a mantener
    
    Returns:
        Número de archivos eliminados
    """
    if not os.path.exists(log_dir):
        return 0
    
    try:
        files = [os.path.join(log_dir, f) for f in os.listdir(log_dir)]
        files = [f for f in files if os.path.isfile(f)]
        
        if len(files) <= keep_files:
            return 0
        
        # Ordenar por fecha de modificación, mantener los más nuevos
        files.sort(key=lambda f: os.path.getmtime(f), reverse=True)
        files_to_remove = files[keep_files:]
        
        removed = 0
        for f in files_to_remove:
            try:
                os.remove(f)
                removed += 1
            except Exception:
                pass
        
        return removed
    except Exception as e:
        logging.error(f"Error limpiando logs antiguos: {e}")
        return 0
