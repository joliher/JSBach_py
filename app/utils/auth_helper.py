"""
Authentication helper functions for JSBach V4.0
Used by both web login and CLI authentication
"""

import hashlib
import json
import os
from typing import Optional, Tuple


def hash_password(password: str) -> str:
    """
    Hash a password using SHA256.
    
    Args:
        password: Plain text password
    
    Returns:
        Hashed password in format "sha256:hash"
    """
    hash_obj = hashlib.sha256(password.encode('utf-8'))
    return f"sha256:{hash_obj.hexdigest()}"


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plain password against a hashed password.
    
    Args:
        plain_password: Plain text password to verify
        hashed_password: Hashed password in format "sha256:hash"
    
    Returns:
        True if passwords match, False otherwise
    """
    return hash_password(plain_password) == hashed_password


def load_users(config_path: str) -> dict:
    """
    Load users from cli_users.json file.
    
    Args:
        config_path: Path to cli_users.json
    
    Returns:
        Dictionary with users data, or empty dict if file doesn't exist
    """
    if not os.path.exists(config_path):
        return {"users": []}
    
    try:
        with open(config_path, 'r') as f:
            return json.load(f)
    except Exception:
        return {"users": []}


def authenticate_user(username: str, password: str, config_path: str) -> Tuple[bool, Optional[dict]]:
    """
    Authenticate a user against cli_users.json.
    
    Args:
        username: Username to authenticate
        password: Plain text password
        config_path: Path to cli_users.json
    
    Returns:
        Tuple of (success: bool, user_data: dict or None)
    """
    users_data = load_users(config_path)
    
    for user in users_data.get("users", []):
        if user.get("username") == username and user.get("enabled", True):
            # Verify password
            if verify_password(password, user.get("password_hash", "")):
                return True, user
    
    return False, None


def create_user(username: str, password: str, role: str = "admin") -> dict:
    """
    Create a user dictionary with hashed password.
    
    Args:
        username: Username
        password: Plain text password
        role: User role (default: admin)
    
    Returns:
        User dictionary
    """
    from datetime import datetime
    
    return {
        "username": username,
        "password_hash": hash_password(password),
        "role": role,
        "created_at": datetime.now().isoformat(),
        "enabled": True
    }
