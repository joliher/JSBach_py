"""
Funciones auxiliares de autenticación para JSBach V4.0
Usadas tanto por el login web como por la autenticación de la CLI
"""

import hashlib
import json
import os
from typing import Optional, Tuple
from datetime import datetime

def hash_password(password: str) -> str:
    """
    Hashea una contraseña usando SHA256.
    Args:
        password: Contraseña en texto plano
    Returns:
        Contraseña hasheada en formato "sha256:hash"
    """
    hash_obj = hashlib.sha256(password.encode('utf-8'))
    return f"sha256:{hash_obj.hexdigest()}"

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifica una contraseña en texto plano contra una contraseña hasheada.
    Args:
        plain_password: Contraseña en texto plano a verificar
        hashed_password: Contraseña hasheada en formato "sha256:hash"
    Returns:
        True si las contraseñas coinciden, False en caso contrario
    """
    return hash_password(plain_password) == hashed_password

def load_users(config_path: str) -> dict:
    """
    Carga usuarios desde un archivo de configuración JSON.
    Args:
        config_path: Ruta al archivo JSON de configuración
    Returns:
        Diccionario con los usuarios
    """
    if not os.path.exists(config_path):
        return {"users": []}
    with open(config_path, 'r', encoding='utf-8') as f:
        return json.load(f)

def authenticate_user(username: str, password: str, config_path: str) -> Tuple[bool, Optional[dict]]:
    """
    Autentica un usuario contra el archivo de configuración.
    Args:
        username: Usuario
        password: Contraseña
        config_path: Ruta al archivo de configuración
    Returns:
        (True, user_data) si autenticado, (False, None) en caso contrario
    """
    users = load_users(config_path).get("users", [])
    for user in users:
        if user["username"] == username and user.get("enabled", True):
            if verify_password(password, user["password_hash"]):
                return True, user
    return False, None

def create_user(username: str, password: str, role: str = "admin") -> dict:
    """
    Crea un nuevo diccionario de usuario.
    Args:
        username: Usuario
        password: Contraseña
        role: Rol del usuario
    Returns:
        Diccionario de usuario
    """
    return {
        "username": username,
        "password_hash": hash_password(password),
        "role": role,
        "created_at": datetime.now().isoformat(),
        "enabled": True
    }
