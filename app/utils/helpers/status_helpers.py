# app/core/status_helpers.py
"""
Funciones auxiliares para construir y formatar mensajes de status de módulos.
Estandariza la presentación de información de estado.
"""

from typing import Dict, Any, Optional, Tuple, List


# =============================================================================
# STATUS DISPLAY HELPERS
# =============================================================================

def format_status_header(module_name: str, icon: str = "🔧") -> str:
    """
    Crear encabezado formateado para status de módulo.
    
    Args:
        module_name: Nombre del módulo
        icon: Emoji a mostrar
    
    Returns:
        String formateado con el encabezado
    """
    return f"\n{icon} {module_name.upper()} - ESTADO DEL MÓDULO\n{'=' * 50}"


def format_status_section(title: str, value: str, icon: str = "ℹ️") -> str:
    """
    Crear línea formateada para una sección de status.
    
    Args:
        title: Título de la sección
        value: Valor a mostrar
        icon: Emoji a mostrar
    
    Returns:
        String formateado
    """
    return f"{icon} {title}: {value}"


def format_active_status(is_active: bool) -> str:
    """
    Formatea el estado activo/inactivo con icono.
    
    Args:
        is_active: True si está activo
    
    Returns:
        String formateado "✅ Activo" o "❌ Inactivo"
    """
    return "✅ Activo" if is_active else "❌ Inactivo"


def format_configuration_list(items: List[str]) -> str:
    """
    Formatea una lista de items de configuración.
    
    Args:
        items: Lista de items a mostrar
    
    Returns:
        String con items formateados (uno por línea con bullet)
    """
    if not items:
        return "  (ninguno)"
    return "\n".join([f"  • {item}" for item in items])


def build_status_response(
    active: bool,
    header: str = "",
    sections: Optional[List[Tuple[str, str]]] = None,
    items: Optional[List[str]] = None
) -> str:
    """
    Construir respuesta completa de status.
    
    Args:
        active: Si el módulo está activo
        header: Encabezado personalizado
        sections: Lista de (titulo, valor) para secciones
        items: Lista de items a mostrar
    
    Returns:
        String con el status completo formateado
    """
    lines = []
    
    if header:
        lines.append(header)
    
    lines.append(f"Estado: {format_active_status(active)}")
    
    if sections:
        for title, value in sections:
            lines.append(format_status_section(title, value))
    
    if items:
        lines.append("\nItems:")
        lines.append(format_configuration_list(items))
    
    return "\n".join(lines)


# =============================================================================
# VALIDACIÓN DE CONFIGURACIÓN
# =============================================================================

def validate_config_structure(
    config: Dict[str, Any],
    required_keys: List[str]
) -> Tuple[bool, str]:
    """
    Validar que la configuración tiene las claves requeridas.
    
    Args:
        config: Dict de configuración a validar
        required_keys: Lista de claves requeridas
    
    Returns:
        Tuple[valid, error_message]
    """
    if not isinstance(config, dict):
        return False, "Configuración debe ser un diccionario"
    
    missing_keys = [key for key in required_keys if key not in config]
    if missing_keys:
        return False, f"Faltan claves requeridas: {', '.join(missing_keys)}"
    
    return True, ""


def validate_config_has_status(config: Dict[str, Any]) -> Tuple[bool, int]:
    """
    Validar que la configuración tiene un status válido.
    
    Args:
        config: Dict de configuración
    
    Returns:
        Tuple[has_status, status_value]
    """
    if "status" not in config:
        return False, -1
    
    status = config["status"]
    if not isinstance(status, int) or status not in [0, 1]:
        return False, -1
    
    return True, status


# =============================================================================
# DEPENDENCIAS ENTRE MÓDULOS
# =============================================================================

def check_module_dependency(
    module_config: Dict[str, Any],
    required_status: int = 1
) -> Tuple[bool, str]:
    """
    Verificar si un módulo requerido está activo.
    
    Args:
        module_config: Configuración del módulo
        required_status: Status requerido (0=inactivo, 1=activo)
    
    Returns:
        Tuple[satisfied, error_message]
    """
    if not module_config:
        return False, "Módulo no configurado"
    
    status = module_config.get("status", -1)
    
    if required_status == 1 and status != 1:
        return False, "Módulo requerido no está activo"
    
    return True, ""


def check_multiple_dependencies(
    dependencies: Dict[str, Dict[str, Any]],
    required_status: int = 1
) -> Tuple[bool, str]:
    """
    Verificar múltiples dependencias de módulos.
    
    Args:
        dependencies: Dict con nombre -> configuración de módulos requeridos
        required_status: Status requerido para todos
    
    Returns:
        Tuple[all_satisfied, error_message]
    """
    for module_name, module_config in dependencies.items():
        satisfied, error = check_module_dependency(module_config, required_status)
        if not satisfied:
            return False, f"Módulo '{module_name}': {error}"
    
    return True, ""


# =============================================================================
# COMPARACIÓN Y SINCRONIZACIÓN
# =============================================================================

def find_new_items(
    current: List[Dict[str, Any]],
    previous: List[Dict[str, Any]],
    key_field: str
) -> List[Dict[str, Any]]:
    """
    Encontrar items nuevos comparando dos listas.
    
    Args:
        current: Lista actual
        previous: Lista anterior
        key_field: Campo a usar como identificador único
    
    Returns:
        Lista de items nuevos
    """
    current_keys = {item.get(key_field) for item in current}
    previous_keys = {item.get(key_field) for item in previous}
    
    new_keys = current_keys - previous_keys
    return [item for item in current if item.get(key_field) in new_keys]


def find_removed_items(
    current: List[Dict[str, Any]],
    previous: List[Dict[str, Any]],
    key_field: str
) -> List[Dict[str, Any]]:
    """
    Encontrar items removidos comparando dos listas.
    
    Args:
        current: Lista actual
        previous: Lista anterior
        key_field: Campo a usar como identificador único
    
    Returns:
        Lista de items removidos
    """
    current_keys = {item.get(key_field) for item in current}
    previous_keys = {item.get(key_field) for item in previous}
    
    removed_keys = previous_keys - current_keys
    return [item for item in previous if item.get(key_field) in removed_keys]
