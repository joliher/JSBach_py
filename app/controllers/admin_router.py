import logging
import importlib
import json
import os
from typing import Optional, Any, Tuple

from fastapi import APIRouter, HTTPException, Depends, Request, Response
from pydantic import BaseModel

from app.utils import global_functions as gf

router = APIRouter(prefix="/admin", tags=["admin"])

ALLOWED_MODULES = ["wan", "nat", "firewall", "vlans", "tagging", "dmz"]

# Config directory for JSBach_V4.0
BASE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
CONFIG_DIR = os.path.join(BASE_DIR, "config")


# -----------------------------
# Modelos
# -----------------------------
class ModuleRequest(BaseModel):
    action: str
    params: Optional[dict[str, Any]] = None


# -----------------------------
# Estado servicios
# -----------------------------
def get_status_from_config(module_name: str) -> str:
    # Mapeo de módulos a sus rutas de configuración
    config_paths = {
        "wan": os.path.join(CONFIG_DIR, "wan", "wan.json"),
        "nat": os.path.join(CONFIG_DIR, "nat", "nat.json"),
        "firewall": os.path.join(CONFIG_DIR, "firewall", "firewall.json"),
        "vlans": os.path.join(CONFIG_DIR, "vlans", "vlans.json"),
        "tagging": os.path.join(CONFIG_DIR, "tagging", "tagging.json"),
        "dmz": os.path.join(CONFIG_DIR, "dmz", "dmz.json")
    }
    
    config_file = config_paths.get(module_name)
    if not config_file or not os.path.exists(config_file):
        return "DESCONOCIDO"
    try:
        with open(config_file, "r") as f:
            config = json.load(f)
        status = config.get("status", None)
        if status == 0:
            return "INACTIVO"
        elif status == 1:
            return "ACTIVO"
        else:
            return "DESCONOCIDO"
    except Exception:
        return "DESCONOCIDO"


# -----------------------------
# Auth dependency
# -----------------------------
def require_login(request: Request) -> str:
    logging.debug(f"Checking session for user in path: {request.url.path}")
    user = request.session.get("user")
    if not user:
        logging.debug(f"No user found in session for path: {request.url.path}")
        raise HTTPException(status_code=403, detail="Acceso denegado")
    logging.debug(f"User '{user}' authenticated.")
    return user


# -----------------------------
# Endpoints
# -----------------------------
@router.get("/status", response_model=dict[str, str])
async def get_status(_: None = Depends(require_login)):
    status_info: dict[str, str] = {}
    for module in ALLOWED_MODULES:
        status_info[module] = get_status_from_config(module)
    return status_info


@router.get("/logs/{module_name}", response_class=Response)
async def get_log(module_name: str, _: None = Depends(require_login)):
    # Usar ruta absoluta basada en BASE_DIR ya definido
    log_file = os.path.join(BASE_DIR, "logs", module_name, "actions.log")
    if not os.path.exists(log_file):
        error_message = f"⚠️ El archivo de log para el módulo '{module_name}' no existe. Ejecute cualquier acción para empezar a generar logs."
        return Response(content=error_message, media_type="text/plain", status_code=404)
    try:
        with open(log_file, 'r') as f:
            log_content = f.read()
        if not log_content.strip():
            log_content = f"⚠️ Archivo de log vacío. Realice alguna acción para empezar a generar logs."
    except Exception as e:
        error_message = f"❌ Error al leer el archivo de log para el módulo '{module_name}': {str(e)}"
        return Response(content=error_message, media_type="text/plain", status_code=500)
    return Response(content=log_content, media_type="text/plain")


@router.get("/config/{module_name}/{config_file}")
async def get_config_file(module_name: str, config_file: str, _: None = Depends(require_login)):
    """Servir archivos de configuración JSON de los módulos."""
    if module_name not in ALLOWED_MODULES:
        raise HTTPException(status_code=404, detail="Módulo no encontrado")
    
    if not config_file.endswith('.json'):
        raise HTTPException(status_code=400, detail="Solo se permiten archivos JSON")
    
    file_path = os.path.join(CONFIG_DIR, module_name, config_file)
    
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Archivo no encontrado")
    
    try:
        with open(file_path, 'r') as f:
            content = json.load(f)
        return content
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error leyendo archivo: {str(e)}")


# -----------------------------
# Core executor
# -----------------------------
def execute_module_action(module_name: str, action: str, params: Optional[dict] = None) -> Tuple[bool, str]:
    if action.startswith("_"):
        gf.log_action(module_name, f"Acción '{action}' no permitida")
        return False, "Acción no permitida"
    try:
        module = importlib.import_module(f"app.core.{module_name}")
    except ModuleNotFoundError:
        gf.log_action(module_name, f"Módulo '{module_name}' no encontrado")
        return False, f"Módulo '{module_name}' no encontrado"

    actions = getattr(module, "ALLOWED_ACTIONS", None)
    if not isinstance(actions, dict):
        gf.log_action(module_name, f"Módulo '{module_name}' no expone acciones administrativas")
        return False, f"Módulo '{module_name}' no expone acciones administrativas"

    func = actions.get(action)
    if not callable(func):
        gf.log_action(module_name, f"Acción '{action}' no permitida")
        return False, f"Acción '{action}' no permitida"

    try:
        # Siempre pasar params (incluso si es None) para consistencia
        result = func(params)
        if isinstance(result, tuple) and len(result) == 2:
            success, message = result
            # No logear para DMZ y firewall start/stop/restart/status (tienen su propio sistema de logs)
            if not ((module_name == "dmz" and action in ["start", "stop", "restart", "status"]) or 
                    (module_name == "firewall" and action in ["start", "stop", "restart", "status"])):
                gf.log_action(module_name, f"Resultado de la acción '{action}':\n{message}")
            return bool(success), str(message)
        gf.log_action(module_name, f"Resultado inesperado de la acción '{action}'")
        return True, str(result)
    except Exception as e:
        error_message = f"Error ejecutando '{action}': {e}"
        gf.log_action(module_name, error_message)
        return False, error_message


@router.post("/{module_name}")
async def admin_module(module_name: str, req: ModuleRequest, _: None = Depends(require_login)):
    success, message = execute_module_action(module_name=module_name, action=req.action, params=req.params)
    if not success:
        raise HTTPException(status_code=400, detail=message)
    return {"success": success, "message": message}
