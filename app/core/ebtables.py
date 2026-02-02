# app/core/ebtables.py
# Módulo de Ebtables - Aislamiento de VLANs a nivel L2
# Arquitectura jerárquica con cadenas por VLAN

import subprocess
import json
import os
import logging
import fcntl
from typing import Dict, Any, Tuple, List
from ..utils.global_functions import (
    create_module_config_directory,
    create_module_log_directory,
    log_action
)
from ..utils.validators import sanitize_interface_name

# Configurar logging
logger = logging.getLogger(__name__)

# Rutas de configuración
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
EBTABLES_CONFIG_FILE = os.path.join(BASE_DIR, "config", "ebtables", "ebtables.json")
VLANS_CONFIG_FILE = os.path.join(BASE_DIR, "config", "vlans", "vlans.json")
WAN_CONFIG_FILE = os.path.join(BASE_DIR, "config", "wan", "wan.json")
TAGGING_CONFIG_FILE = os.path.join(BASE_DIR, "config", "tagging", "tagging.json")


# =============================================================================
# UTILIDADES BÁSICAS
# =============================================================================

def _ensure_dirs():
    """Crear directorios necesarios para configuración y logs."""
    os.makedirs(os.path.dirname(EBTABLES_CONFIG_FILE), exist_ok=True)
    create_module_log_directory("ebtables")
    create_module_config_directory("ebtables")

# Alias para compatibilidad
_sanitize_interface_name = sanitize_interface_name


def _load_vlans_config() -> dict:
    """Cargar configuración de VLANs desde vlans.json."""
    if not os.path.exists(VLANS_CONFIG_FILE):
        return {"vlans": [], "status": 0}
    try:
        with open(VLANS_CONFIG_FILE, "r") as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Error cargando VLANs config: {e}")
        return {"vlans": [], "status": 0}


def _load_ebtables_config() -> dict:
    """Cargar configuración de ebtables desde ebtables.json."""
    if not os.path.exists(EBTABLES_CONFIG_FILE):
        return {"vlans": {}, "status": 0}
    try:
        with open(EBTABLES_CONFIG_FILE, "r") as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Error cargando ebtables config: {e}")
        return {"vlans": {}, "status": 0}


def _save_ebtables_config(data: dict) -> None:
    """Guardar configuración de ebtables en ebtables.json."""
    _ensure_dirs()
    try:
        with open(EBTABLES_CONFIG_FILE, "w") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            json.dump(data, f, indent=4)
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        logger.info("Configuración de ebtables guardada correctamente")
    except Exception as e:
        logger.error(f"Error guardando configuración de ebtables: {e}")


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


def _load_tagging_config() -> dict:
    """Cargar configuración de tagging desde tagging.json."""
    if not os.path.exists(TAGGING_CONFIG_FILE):
        return {"interfaces": [], "status": 0}
    try:
        with open(TAGGING_CONFIG_FILE, "r") as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Error cargando tagging config: {e}")
        return {"interfaces": [], "status": 0}


def _build_vlan_interface_map(vlans: List[dict], tagging_cfg: dict) -> Dict[int, List[str]]:
    """Construir mapa VLAN → interfaces físicas.
    
    Retorna: {vlan_id: [lista de interfaces en esa VLAN]}
    
    Valida que todas las VLANs en tagging.json existan realmente en vlans.json
    """
    # Crear set de VLANs válidas
    valid_vlan_ids = {vlan.get("id") for vlan in vlans if vlan.get("id") is not None}
    
    # Inicializar mapa vacío para todas las VLANs válidas
    vlan_iface_map: Dict[int, List[str]] = {vlan_id: [] for vlan_id in valid_vlan_ids}
    
    # Procesar cada interfaz en tagging.json
    for iface in tagging_cfg.get("interfaces", []):
        iface_name = iface.get("name", "")
        
        # Procesar VLANs untagged
        vlan_untag = iface.get("vlan_untag", "").strip()
        if vlan_untag:
            try:
                vlan_id = int(vlan_untag)
                if vlan_id in valid_vlan_ids:
                    if iface_name not in vlan_iface_map[vlan_id]:
                        vlan_iface_map[vlan_id].append(iface_name)
                    logger.info(f"Interfaz {iface_name} → VLAN {vlan_id} (untagged)")
                else:
                    logger.warning(f"VLAN {vlan_id} en tagging.json NO existe en vlans.json")
            except (ValueError, TypeError):
                logger.warning(f"VLAN untagged inválida en interfaz {iface_name}: {vlan_untag}")
        
        # Procesar VLANs tagged
        vlan_tag_str = iface.get("vlan_tag", "").strip()
        if vlan_tag_str:
            for vlan_id_str in vlan_tag_str.split(","):
                vlan_id_str = vlan_id_str.strip()
                try:
                    vlan_id = int(vlan_id_str)
                    if vlan_id in valid_vlan_ids:
                        if iface_name not in vlan_iface_map[vlan_id]:
                            vlan_iface_map[vlan_id].append(iface_name)
                        logger.info(f"Interfaz {iface_name} → VLAN {vlan_id} (tagged)")
                    else:
                        logger.warning(f"VLAN {vlan_id} en tagging.json NO existe en vlans.json")
                except (ValueError, TypeError):
                    logger.warning(f"VLAN tagged inválida en interfaz {iface_name}: {vlan_id_str}")
    
    return vlan_iface_map


def _check_wan_active() -> Tuple[bool, str]:
    """Verificar si la WAN está activa y obtener la interfaz."""
    wan_cfg = _load_wan_config()
    if not wan_cfg:
        return False, None
    
    if wan_cfg.get("status") != 1:
        return False, None
    
    iface = wan_cfg.get("interface")
    if not iface:
        return False, None
    
    return True, iface


def _check_vlans_active() -> Tuple[bool, str]:
    """Verificar si el módulo VLANs está activo."""
    vlans_cfg = _load_vlans_config()
    if not vlans_cfg:
        return False, "Módulo VLANs no configurado"
    
    status = vlans_cfg.get("status", 0)
    if status != 1:
        return False, "Módulo VLANs no está activo"
    
    vlans = vlans_cfg.get("vlans", [])
    if not vlans:
        return False, "No hay VLANs configuradas"
    
    return True, None


def _check_tagging_active() -> Tuple[bool, str]:
    """Verificar si el módulo Tagging está activo."""
    tagging_cfg = _load_tagging_config()
    if not tagging_cfg:
        return False, "Módulo Tagging no configurado"
    
    status = tagging_cfg.get("status", 0)
    if status != 1:
        return False, "Módulo Tagging no está activo"
    
    interfaces = tagging_cfg.get("interfaces", [])
    if not interfaces:
        return False, "No hay interfaces configuradas en Tagging"
    
    return True, None


def _check_dependencies() -> Tuple[bool, str]:
    """Verificar que todos los módulos requeridos estén activos.
    
    Returns:
        (True, None) si todo ok
        (False, mensaje_error) si falta alguno
    """
    # Verificar WAN
    wan_active, wan_iface = _check_wan_active()
    if not wan_active:
        return False, "Módulo WAN debe estar activo"
    
    # Verificar VLANs
    vlans_ok, vlans_msg = _check_vlans_active()
    if not vlans_ok:
        return False, vlans_msg
    
    # Verificar Tagging
    tagging_ok, tagging_msg = _check_tagging_active()
    if not tagging_ok:
        return False, tagging_msg
    
    return True, None


def _update_status(status: int) -> None:
    """Actualizar el estado del módulo (0=inactivo, 1=activo)."""
    cfg = _load_ebtables_config()
    cfg["status"] = status
    _save_ebtables_config(cfg)


def _run_ebtables(args: List[str], timeout: int = 30) -> Tuple[bool, str]:
    """Ejecutar comando ebtables."""
    try:
        result = subprocess.run(
            ["sudo", "/usr/sbin/ebtables"] + args,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        if result.returncode == 0:
            return True, result.stdout
        return False, result.stderr
    except subprocess.TimeoutExpired:
        return False, "Timeout ejecutando ebtables"
    except Exception as e:
        return False, str(e)


# =============================================================================
# GESTIÓN DE CADENAS
# =============================================================================

def _create_vlan_chain(vlan_id: int) -> bool:
    """Crear cadena FORWARD_VLAN_X para una VLAN específica."""
    chain_name = f"FORWARD_VLAN_{vlan_id}"
    
    # Verificar si ya existe
    success, output = _run_ebtables(["-L", chain_name])
    if success:
        logger.info(f"Cadena {chain_name} ya existe")
        return True
    
    # Crear la cadena
    success, msg = _run_ebtables(["-N", chain_name])
    if not success:
        logger.error(f"Error creando cadena {chain_name}: {msg}")
        return False
    
    logger.info(f"Cadena {chain_name} creada")
    return True


def _delete_vlan_chain(vlan_id: int) -> bool:
    """Eliminar cadena FORWARD_VLAN_X de una VLAN."""
    chain_name = f"FORWARD_VLAN_{vlan_id}"
    
    # Verificar si existe
    success, output = _run_ebtables(["-L", chain_name])
    if not success:
        return True  # No existe, no hay que hacer nada
    
    # Flush de reglas primero
    _run_ebtables(["-F", chain_name])
    
    # Eliminar referencias en FORWARD (todas las que redireccionan a esta cadena)
    success, output = _run_ebtables(["-L", "FORWARD", "--Ln"])
    if success:
        # Buscar reglas que salten a esta cadena (-j FORWARD_VLAN_X)
        lines = output.strip().split('\n')
        for line in lines:
            if f"-j {chain_name}" in line:
                # Extraer interfaz de entrada (-i)
                if "-i " in line:
                    parts = line.split("-i ")
                    if len(parts) > 1:
                        iface = parts[1].split()[0]
                        _run_ebtables(["-D", "FORWARD", "-i", iface, "-j", chain_name])
    
    # Eliminar la cadena
    success, msg = _run_ebtables(["-X", chain_name])
    if not success:
        logger.error(f"Error eliminando cadena {chain_name}: {msg}")
        return False
    
    logger.info(f"Cadena {chain_name} eliminada")
    return True


def _add_vlan_interface_to_forward(vlan_id: int, vlan_interface: str, position: int = 1) -> bool:
    """Agregar regla en FORWARD que redirecciona tráfico VLAN a su cadena.
    
    Regla: ebtables -A FORWARD -i <vlan_interface> -j FORWARD_VLAN_X
    """
    chain_name = f"FORWARD_VLAN_{vlan_id}"
    
    # Verificar si ya existe esta regla
    success, output = _run_ebtables(["-L", "FORWARD", "--Ln"])
    if success and f"-i {vlan_interface}" in output and chain_name in output:
        logger.info(f"Regla FORWARD -i {vlan_interface} → {chain_name} ya existe")
        return True
    
    # Insertar regla de redirección a la cadena VLAN
    success, msg = _run_ebtables(["-I", "FORWARD", str(position), "-i", vlan_interface, "-j", chain_name])
    if not success:
        logger.error(f"Error agregando regla FORWARD -i {vlan_interface} → {chain_name}: {msg}")
        return False
    
    logger.info(f"Regla FORWARD -i {vlan_interface} → {chain_name} agregada")
    return True


def _remove_vlan_interface_from_forward(vlan_interface: str) -> bool:
    """Remover reglas de FORWARD que redireccionan interfaz VLAN."""
    # Obtener todas las reglas de FORWARD
    success, output = _run_ebtables(["-L", "FORWARD", "--Ln"])
    if not success:
        return True
    
    # Buscar y eliminar reglas con esta interfaz
    lines = output.strip().split('\n')
    rules_removed = False
    for line in lines:
        if f"-i {vlan_interface}" in line:
            # Extraer el target (cadena destino)
            # Formato: -i enxXXX -j FORWARD_VLAN_X
            if "-j FORWARD_VLAN_" in line:
                chain_target = line.split("-j")[-1].strip()
                # Verificar que la regla existe antes de eliminar
                verify_success, verify_output = _run_ebtables(["-L", "FORWARD", "--Ln"])
                if verify_success and f"-i {vlan_interface} -j {chain_target}" in verify_output:
                    _run_ebtables(["-D", "FORWARD", "-i", vlan_interface, "-j", chain_target])
                    rules_removed = True
                    logger.info(f"Regla FORWARD -i {vlan_interface} -j {chain_target} eliminada")
    
    if not rules_removed:
        logger.info(f"No se encontraron reglas FORWARD para {vlan_interface}")
    return True


def _apply_isolation(vlan_id: int, wan_iface: str, vlan_interfaces: List[str]) -> bool:
    """Aplicar aislamiento a una VLAN (solo permite tráfico con WAN).
    
    Estructura optimizada:
    FORWARD:
      -i <interfaz_vlan> -j FORWARD_VLAN_X    (redirecciona tráfico de la interfaz VLAN)
      ...
      -j DROP                                   (rechaza todo lo demás)
    
    FORWARD_VLAN_X:
      -i <interfaz_wan> -j ACCEPT              (permite entrada WAN)
      -o <interfaz_wan> -j ACCEPT              (permite salida WAN)
      (DROP implícito por default)
    
    Args:
        vlan_id: ID de la VLAN
        wan_iface: Interfaz WAN (ej: eth0)
        vlan_interfaces: Lista de interfaces físicas en esta VLAN
    """
    chain_name = f"FORWARD_VLAN_{vlan_id}"
    
    logger.info(f"Aplicando aislamiento a VLAN {vlan_id} - Interfaces: {vlan_interfaces}")
    
    # Asegurar que la cadena existe
    if not _create_vlan_chain(vlan_id):
        logger.error(f"No se pudo crear cadena {chain_name}")
        return False
    
    # Flush de reglas existentes en la cadena VLAN
    success, msg = _run_ebtables(["-F", chain_name])
    if not success:
        logger.warning(f"Advertencia al limpiar {chain_name}: {msg}")
    else:
        logger.info(f"Reglas previas de {chain_name} eliminadas")
    
    # En FORWARD_VLAN_X, agregar solo reglas WAN (entrada y salida)
    
    # Regla 1: Permitir tráfico ENTRADA desde WAN
    # Verificar si ya existe antes de añadir
    verify_success, verify_output = _run_ebtables(["-L", chain_name, "--Ln"])
    if not (verify_success and f"-i {wan_iface} -j ACCEPT" in verify_output):
        success, msg = _run_ebtables(["-A", chain_name, "-i", wan_iface, "-j", "ACCEPT"])
        if not success:
            logger.error(f"Error añadiendo regla entrada WAN: {msg}")
            return False
        logger.info(f"Regla {chain_name} -i {wan_iface} -j ACCEPT añadida")
    else:
        logger.info(f"Regla {chain_name} -i {wan_iface} -j ACCEPT ya existe")
    
    # Regla 2: Permitir tráfico SALIDA hacia WAN
    # Verificar si ya existe antes de añadir
    verify_success, verify_output = _run_ebtables(["-L", chain_name, "--Ln"])
    if not (verify_success and f"-o {wan_iface} -j ACCEPT" in verify_output):
        success, msg = _run_ebtables(["-A", chain_name, "-o", wan_iface, "-j", "ACCEPT"])
        if not success:
            logger.error(f"Error añadiendo regla salida WAN: {msg}")
            return False
        logger.info(f"Regla {chain_name} -o {wan_iface} -j ACCEPT añadida")
    else:
        logger.info(f"Regla {chain_name} -o {wan_iface} -j ACCEPT ya existe")
    
    # Agregar reglas en FORWARD que redireccionen cada interfaz VLAN a esta cadena
    for i, phys_iface in enumerate(vlan_interfaces, start=1):
        if not _add_vlan_interface_to_forward(vlan_id, phys_iface, position=i):
            logger.error(f"Error agregando regla FORWARD para interfaz {phys_iface}")
            return False
    
    logger.info(f"Aislamiento aplicado a VLAN {vlan_id} - Reglas WAN creadas")
    return True

def _remove_isolation(vlan_id: int, vlan_interfaces: List[str] = None) -> bool:
    """Remover aislamiento de una VLAN (eliminar todas las reglas).
    
    Args:
        vlan_id: ID de la VLAN
        vlan_interfaces: Lista de interfaces de la VLAN (para remover reglas de FORWARD)
    """
    chain_name = f"FORWARD_VLAN_{vlan_id}"
    
    # Eliminar reglas en FORWARD que redireccionan a esta cadena
    if vlan_interfaces:
        for iface in vlan_interfaces:
            # Verificar y eliminar regla de redirección en FORWARD
            success, output = _run_ebtables(["-L", "FORWARD", "--Ln"])
            if success and f"-i {iface} -j {chain_name}" in output:
                success, msg = _run_ebtables(["-D", "FORWARD", "-i", iface, "-j", chain_name])
                if success:
                    logger.info(f"Regla FORWARD -i {iface} -j {chain_name} eliminada")
                else:
                    logger.error(f"Error eliminando regla FORWARD para {iface}: {msg}")
    
    # Siempre intentar hacer flush de la cadena (elimina todas las reglas dentro)
    logger.info(f"Eliminando todas las reglas de {chain_name}...")
    success, msg = _run_ebtables(["-F", chain_name])
    
    if success:
        logger.info(f"Reglas de {chain_name} eliminadas correctamente")
    else:
        # Si falla, podría ser porque la cadena no existe, que es ok
        if "Table does not exist" in msg or "No such file" in msg or "does not exist" in msg:
            logger.info(f"Cadena {chain_name} no existe (ya fue eliminada o nunca se creó)")
        else:
            logger.error(f"Error al hacer flush de {chain_name}: {msg}")
            return False
    
    logger.info(f"Aislamiento removido de VLAN {vlan_id}")
    return True


# =============================================================================
# ACCIONES PÚBLICAS
# =============================================================================

def start(params: Dict[str, Any] = None) -> Tuple[bool, str]:
    """Iniciar el sistema de bridge/ebtables con estructura jerárquica.
    
    Estructura:
    FORWARD → FORWARD_VLAN_1 (reglas VLAN 1)
           → FORWARD_VLAN_10 (reglas VLAN 10)
           → DROP (regla final)
    
    Dependencias: WAN, VLANs, Tagging deben estar activos
    """
    _ensure_dirs()
    logger.info("=== INICIO: ebtables start ===")
    
    # Verificar dependencias (WAN, VLANs, Tagging)
    deps_ok, deps_msg = _check_dependencies()
    if not deps_ok:
        logger.error(f"Dependencias no satisfechas: {deps_msg}")
        return False, f"Error: {deps_msg}. Configure e inicie los módulos requeridos primero."
    
    # Obtener interfaz WAN (ya sabemos que está activa)
    wan_active, wan_iface = _check_wan_active()
    
    if not _sanitize_interface_name(wan_iface):
        logger.error(f"Interfaz WAN inválida: {wan_iface}")
        return False, f"Error: Interfaz WAN inválida: {wan_iface}"
    
    # Cargar configuración de VLANs
    vlans_cfg = _load_vlans_config()
    vlans = vlans_cfg.get("vlans", [])
    
    # Cargar/inicializar configuración de ebtables
    ebtables_cfg = _load_ebtables_config()
    if "vlans" not in ebtables_cfg:
        ebtables_cfg["vlans"] = {}
    
    # Cargar configuración de tagging
    tagging_cfg = _load_tagging_config()
    
    # Construir mapa VLAN → interfaces físicas
    vlan_iface_map = _build_vlan_interface_map(vlans, tagging_cfg)
    logger.info(f"Mapa VLAN→Interfaces: {vlan_iface_map}")
    
    # Sincronizar: eliminar VLANs obsoletas de ebtables.json
    active_vlan_ids = {str(vlan.get("id")) for vlan in vlans if vlan.get("id") is not None}
    vlans_to_remove = [vid for vid in ebtables_cfg["vlans"].keys() if vid not in active_vlan_ids]
    
    for vlan_id in vlans_to_remove:
        logger.info(f"Eliminando VLAN {vlan_id} obsoleta de ebtables.json")
        _delete_vlan_chain(int(vlan_id))
        del ebtables_cfg["vlans"][vlan_id]
    
    results = []
    errors = []
    
    # Procesar cada VLAN
    for vlan in vlans:
        vlan_id = vlan.get("id")
        vlan_name = vlan.get("name", f"VLAN{vlan_id}")
        vlan_id_str = str(vlan_id)
        
        logger.info(f"Procesando VLAN {vlan_id} ({vlan_name})")
        
        # Validar que la VLAN tenga ID válido
        if not vlan_id or not isinstance(vlan_id, int):
            errors.append(f"VLAN con ID inválido: {vlan_id}")
            continue
        
        # Inicializar configuración de VLAN si no existe
        if vlan_id_str not in ebtables_cfg["vlans"]:
            ebtables_cfg["vlans"][vlan_id_str] = {
                "name": vlan_name,
                "isolated": False  # Por defecto NO aislada
            }
        else:
            # Actualizar nombre de la VLAN
            ebtables_cfg["vlans"][vlan_id_str]["name"] = vlan_name
        
        # Crear cadena para la VLAN
        if not _create_vlan_chain(vlan_id):
            errors.append(f"VLAN {vlan_id}: Error creando cadena ebtables")
            logger.error(f"Error creando cadena para VLAN {vlan_id}")
            continue
        
        # Las reglas en FORWARD se agregarán solo si la VLAN está aislada (en _apply_isolation)
        # Si no está aislada, la cadena existe pero vacía (sin reglas en FORWARD)

        
        # Aplicar aislamiento si está configurado
        is_isolated = ebtables_cfg["vlans"][vlan_id_str].get("isolated", False)
        
        # Obtener interfaces de esta VLAN desde el mapa
        vlan_interfaces = vlan_iface_map.get(vlan_id, [])
        
        if is_isolated:
            if not _apply_isolation(vlan_id, wan_iface, vlan_interfaces):
                errors.append(f"VLAN {vlan_id}: Error aplicando aislamiento")
                logger.error(f"Error aplicando aislamiento a VLAN {vlan_id}")
                continue
            logger.info(f"VLAN {vlan_id} configurada como AISLADA con interfaces: {vlan_interfaces}")
            results.append(f"VLAN {vlan_id} ({vlan_name}): AISLADA (interfaces: {','.join(vlan_interfaces)})")
        else:
            # Asegurar que no tenga reglas de aislamiento
            _remove_isolation(vlan_id)
            logger.info(f"VLAN {vlan_id} configurada como NO AISLADA")
            results.append(f"VLAN {vlan_id} ({vlan_name}): NO AISLADA")
    
    # Guardar configuración actualizada
    ebtables_cfg["status"] = 1
    ebtables_cfg["wan_interface"] = wan_iface
    _save_ebtables_config(ebtables_cfg)
    
    # Construir mensaje de resultado
    message_parts = [f"✅ Ebtables iniciado correctamente"]
    message_parts.append(f"WAN: {wan_iface}")
    message_parts.append(f"VLANs procesadas: {len(results)}")
    
    if results:
        message_parts.append("\nVLANs configuradas:")
        message_parts.extend(results)
    
    if errors:
        message_parts.append("\n⚠️ Advertencias:")
        message_parts.extend(errors)
        logger.warning(f"Ebtables iniciado con advertencias: {errors}")
    
    final_message = "\n".join(message_parts)
    logger.info(final_message)
    logger.info("=== FIN: ebtables start ===")
    
    return True, final_message


def stop(params: Dict[str, Any] = None) -> Tuple[bool, str]:
    """Detener el sistema de bridge/ebtables."""
    _ensure_dirs()
    logger.info("=== INICIO: bridge stop ===")
    
    ebtables_cfg = _load_ebtables_config()
    vlans = ebtables_cfg.get("vlans", {})
    
    # Eliminar todas las cadenas de VLANs
    for vlan_id_str in vlans.keys():
        vlan_id = int(vlan_id_str)
        _delete_vlan_chain(vlan_id)
    
    # Actualizar estado
    _update_status(0)
    
    logger.info("Bridge detenido correctamente")
    logger.info("=== FIN: bridge stop ===")
    return True, "Bridge detenido correctamente"


def restart(params: Dict[str, Any] = None) -> Tuple[bool, str]:
    """Reiniciar el sistema de bridge/ebtables."""
    _ensure_dirs()
    logger.info("=== INICIO: bridge restart ===")
    
    # Detener
    ok, msg = stop()
    if not ok:
        return False, f"Error al detener: {msg}"
    
    # Iniciar
    ok, msg = start()
    if not ok:
        return False, f"Error al iniciar: {msg}"
    
    logger.info("=== FIN: bridge restart ===")
    return True, "Bridge reiniciado correctamente"


def status(params: Dict[str, Any] = None) -> Tuple[bool, str]:
    """Obtener estado del bridge/ebtables y sus dependencias."""
    _ensure_dirs()
    
    ebtables_cfg = _load_ebtables_config()
    module_status = ebtables_cfg.get("status", 0)
    vlans = ebtables_cfg.get("vlans", {})
    
    lines = []
    
    # ========== ESTADO DEL MÓDULO ==========
    if module_status == 0:
        lines.append("🌉 EBTABLES - MÓDULO INACTIVO")
        lines.append("=" * 50)
        lines.append("")
        lines.append("❌ El módulo EBTABLES está PARADO")
        lines.append("")
        lines.append("Para activar el módulo:")
        lines.append("1. Asegúrate de que WAN, VLANs y Tagging estén activos")
        lines.append("2. Haz clic en 'EBTABLES START' en la interfaz web")
        lines.append("")
        lines.append(f"VLANs con configuración guardada: {len(vlans)}")
        return True, "\n".join(lines)
    
    # Módulo activo - mostrar estado completo
    lines.append("🌉 EBTABLES - MÓDULO ACTIVO")
    lines.append("=" * 50)
    lines.append("")
    
    # ========== DEPENDENCIAS ==========
    lines.append("📦 DEPENDENCIAS:")
    lines.append("-" * 50)
    
    # Verificar WAN
    wan_active, wan_iface = _check_wan_active()
    if wan_active:
        lines.append(f"✅ WAN: Activo (interfaz: {wan_iface})")
    else:
        lines.append("❌ WAN: INACTIVO (requerido para bridge)")
    
    # Verificar VLANs
    vlans_ok, vlans_msg = _check_vlans_active()
    if vlans_ok:
        vlans_cfg = _load_vlans_config()
        vlans_list = vlans_cfg.get("vlans", [])
        lines.append(f"✅ VLANs: Activo ({len(vlans_list)} VLANs configuradas)")
    else:
        lines.append(f"❌ VLANs: {vlans_msg}")
    
    # Verificar Tagging
    tagging_ok, tagging_msg = _check_tagging_active()
    if tagging_ok:
        tagging_cfg = _load_tagging_config()
        ifaces = tagging_cfg.get("interfaces", [])
        lines.append(f"✅ Tagging: Activo ({len(ifaces)} interfaces configuradas)")
    else:
        lines.append(f"❌ Tagging: {tagging_msg}")
    
    # Verificar si todas las dependencias están ok
    all_deps_ok = wan_active and vlans_ok and tagging_ok
    lines.append("")
    
    # ========== ESTADO GENERAL ==========
    lines.append("🌉 ESTADO OPERACIONAL:")
    lines.append("-" * 50)
    
    if not all_deps_ok:
        lines.append("⚠️ No todas las dependencias están activas.")
        lines.append("   El módulo EBTABLES no puede operar correctamente.")
        lines.append("")
        lines.append(f"VLANs aisladas en configuración: {len(vlans)}")
        return True, "\n".join(lines)
    
    if not vlans:
        lines.append("ℹ️  Sin VLANs configuradas en ebtables")
        return True, "\n".join(lines)
    
    lines.append(f"✅ Todas las dependencias activas")
    lines.append(f"VLANs configuradas: {len(vlans)}")
    lines.append("-" * 50)
    lines.append("")
    
    # ========== DETALLE DE VLANs ==========
    for vlan_id_str, vlan_data in sorted(vlans.items(), key=lambda x: int(x[0])):
        vlan_name = vlan_data.get("name", "")
        isolated = vlan_data.get("isolated", False)
        
        status_str = "🔒 AISLADA" if isolated else "🔓 NO AISLADA"
        lines.append(f"VLAN {vlan_id_str} ({vlan_name}): {status_str}")
        
        # Mostrar reglas activas
        chain_name = f"FORWARD_VLAN_{vlan_id_str}"
        success, output = _run_ebtables(["-L", chain_name])
        if success and output.strip():
            # Contar reglas (excluir líneas de cabecera)
            rules = [l for l in output.strip().split('\n') if l and not l.startswith('Bridge')]
            if len(rules) > 2:  # Más que solo cabeceras
                lines.append(f"  Reglas activas: {len(rules) - 2}")
        lines.append("")
    
    return True, "\n".join(lines)


def aislar(params: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Aislar una VLAN (solo permite tráfico con WAN).
    
    Requiere: WAN, VLANs y Tagging activos.
    """
    _ensure_dirs()
    
    if not params or "vlan_id" not in params:
        return False, "Error: Falta parámetro 'vlan_id'"
    
    try:
        vlan_id = int(params["vlan_id"])
    except (ValueError, TypeError):
        return False, f"Error: 'vlan_id' debe ser un número entero"
    
    # Verificar dependencias (WAN, VLANs, Tagging)
    deps_ok, deps_msg = _check_dependencies()
    if not deps_ok:
        logger.error(f"Dependencias no satisfechas al aislar VLAN {vlan_id}: {deps_msg}")
        return False, f"Error: {deps_msg}. Configure e inicie los módulos requeridos primero."
    
    # Obtener interfaz WAN (ya sabemos que está activa)
    wan_active, wan_iface = _check_wan_active()
    
    # Verificar que la VLAN existe en vlans.json (sincronización)
    vlans_cfg = _load_vlans_config()
    vlans = vlans_cfg.get("vlans", [])
    vlan_exists = any(v.get("id") == vlan_id for v in vlans)
    if not vlan_exists:
        return False, f"Error: VLAN {vlan_id} no existe. Configure la VLAN primero."
    
    # Cargar configuración
    ebtables_cfg = _load_ebtables_config()
    vlan_id_str = str(vlan_id)
    
    if vlan_id_str not in ebtables_cfg.get("vlans", {}):
        return False, f"Error: VLAN {vlan_id} no está configurada en ebtables. Inicie ebtables primero."
    
    # Cargar tagging y construir mapa de interfaces
    tagging_cfg = _load_tagging_config()
    vlan_iface_map = _build_vlan_interface_map(vlans, tagging_cfg)
    vlan_interfaces = vlan_iface_map.get(vlan_id, [])
    
    logger.info(f"Aislando VLAN {vlan_id} con interfaces: {vlan_interfaces}")
    
    # Aplicar aislamiento
    if not _apply_isolation(vlan_id, wan_iface, vlan_interfaces):
        return False, f"Error aplicando aislamiento a VLAN {vlan_id}"
    
    # Actualizar configuración
    ebtables_cfg["vlans"][vlan_id_str]["isolated"] = True
    _save_ebtables_config(ebtables_cfg)
    
    logger.info(f"VLAN {vlan_id} aislada correctamente")
    return True, f"VLAN {vlan_id} aislada correctamente (solo tráfico con WAN permitido)\nInterfases: {','.join(vlan_interfaces) if vlan_interfaces else 'ninguna'}"


def desaislar(params: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Desaislar una VLAN (permitir todo el tráfico).
    
    Requiere: WAN, VLANs y Tagging activos.
    """
    _ensure_dirs()
    
    if not params or "vlan_id" not in params:
        return False, "Error: Falta parámetro 'vlan_id'"
    
    try:
        vlan_id = int(params["vlan_id"])
    except (ValueError, TypeError):
        return False, f"Error: 'vlan_id' debe ser un número entero"
    
    # Verificar dependencias (WAN, VLANs, Tagging)
    deps_ok, deps_msg = _check_dependencies()
    if not deps_ok:
        logger.error(f"Dependencias no satisfechas al desaislar VLAN {vlan_id}: {deps_msg}")
        return False, f"Error: {deps_msg}. Configure e inicie los módulos requeridos primero."
    
    # Cargar configuración
    ebtables_cfg = _load_ebtables_config()
    vlan_id_str = str(vlan_id)
    
    if vlan_id_str not in ebtables_cfg.get("vlans", {}):
        return False, f"Error: VLAN {vlan_id} no está configurada en bridge"
    
    # Obtener interfaces de la VLAN para remover las reglas en FORWARD
    vlans_cfg = _load_vlans_config()
    vlans = vlans_cfg.get("vlans", [])
    tagging_cfg = _load_tagging_config()
    vlan_iface_map = _build_vlan_interface_map(vlans, tagging_cfg)
    vlan_interfaces = vlan_iface_map.get(vlan_id, [])
    
    logger.info(f"Desaislando VLAN {vlan_id} con interfaces: {vlan_interfaces}")
    
    # Remover aislamiento (elimina reglas en FORWARD y cadena FORWARD_VLAN_X)
    if not _remove_isolation(vlan_id, vlan_interfaces):
        return False, f"Error removiendo aislamiento de VLAN {vlan_id}"
    
    # Actualizar configuración
    ebtables_cfg["vlans"][vlan_id_str]["isolated"] = False
    _save_ebtables_config(ebtables_cfg)
    
    logger.info(f"VLAN {vlan_id} desaislada correctamente")
    return True, f"VLAN {vlan_id} desaislada correctamente (todo el tráfico permitido)"


# =============================================================================
# ACCIONES PERMITIDAS
# =============================================================================

ALLOWED_ACTIONS = {
    "start": start,
    "stop": stop,
    "restart": restart,
    "status": status,
    "aislar": aislar,
    "desaislar": desaislar,
}
