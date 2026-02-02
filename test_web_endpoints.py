#!/usr/bin/env python3
"""
Script para probar acceso a endpoints /web
"""

import requests
import json
import sys
from urllib.parse import urljoin

# Configuración
BASE_URL = "http://localhost:8100"
HEADERS = {"Content-Type": "application/json"}

# Credenciales
USERNAME = "admin"
PASSWORD = "password123"

# Session compartida
session = requests.Session()

def log(msg, level="INFO"):
    """Logger simple"""
    print(f"[{level}] {msg}")

def test_login():
    """Probar autenticación"""
    log("Autenticando...")
    try:
        response = session.post(
            urljoin(BASE_URL, "/login"),
            json={"username": USERNAME, "password": PASSWORD},
            headers=HEADERS,
            timeout=5
        )
        if response.status_code == 200:
            log("✅ Login exitoso")
            return True
        else:
            log(f"❌ Login fallido: {response.text}")
            return False
    except Exception as e:
        log(f"❌ Error: {e}", "ERROR")
        return False

def test_web_files():
    """Probar acceso a archivos web estáticos"""
    log("")
    log("=" * 60)
    log("TEST: Archivos Web Estáticos", "TEST")
    log("=" * 60)
    
    files = [
        "/web/index.html",
        "/web/login.html",
        "/web/status.html",
        "/web/info.html",
        "/web/header.html",
        "/web/00-css/global.css",
        "/web/00-css/buttons.css",
        "/web/00-css/cards.css",
        "/web/00-css/forms.css",
        "/web/00-css/header.css",
        "/web/00-js/app.js",
        "/web/00-js/utils.js",
    ]
    
    results = {}
    for file_path in files:
        try:
            response = session.get(
                urljoin(BASE_URL, file_path),
                timeout=5
            )
            if response.status_code == 200:
                log(f"✅ {file_path} - {len(response.content)} bytes")
                results[file_path] = True
            else:
                log(f"❌ {file_path} - Status {response.status_code}")
                results[file_path] = False
        except Exception as e:
            log(f"❌ {file_path} - Error: {str(e)[:50]}")
            results[file_path] = False
    
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    log(f"\nTotal: {passed}/{total} archivos accesibles")
    return passed == total

def test_module_web_files():
    """Probar acceso a archivos web específicos de módulos"""
    log("")
    log("=" * 60)
    log("TEST: Archivos Web por Módulo", "TEST")
    log("=" * 60)
    
    modules = {
        "wan": ["index.html", "status.html", "info.html", "config.html", "menu.html"],
        "vlans": ["index.html", "status.html", "info.html", "config.html", "menu.html"],
        "firewall": ["index.html", "status.html", "info.html", "config_whitelist.html", "menu.html", "view_vlans.html"],
        "nat": ["index.html", "status.html", "info.html", "config.html", "menu.html"],
        "dmz": ["index.html", "status.html", "info.html", "config.html", "destinations.html", "detailed_status.html", "menu.html"],
        "tagging": ["index.html", "status.html", "info.html", "config.html", "menu.html"],
        "ebtables": ["index.html", "status.html", "info.html", "config.html", "menu.html"],
    }
    
    results = {}
    for module, files in modules.items():
        results[module] = {}
        log(f"\nMódulo: {module}")
        for file in files:
            file_path = f"/web/{module}/{file}"
            try:
                response = session.get(
                    urljoin(BASE_URL, file_path),
                    timeout=5
                )
                if response.status_code == 200:
                    log(f"  ✅ {file}")
                    results[module][file] = True
                else:
                    log(f"  ❌ {file} - Status {response.status_code}")
                    results[module][file] = False
            except Exception as e:
                log(f"  ❌ {file} - Error: {str(e)[:50]}")
                results[module][file] = False
    
    # Resumen por módulo
    log("")
    log("Resumen por módulo:")
    total_passed = 0
    total_files = 0
    for module, files in results.items():
        passed = sum(1 for v in files.values() if v)
        total = len(files)
        total_passed += passed
        total_files += total
        status = "✅" if passed == total else "⚠️ "
        log(f"  {status} {module}: {passed}/{total}")
    
    log(f"\nTotal: {total_passed}/{total_files} archivos de módulos accesibles")
    return total_passed == total_files

def test_config_api():
    """Probar acceso a configuraciones vía /config"""
    log("")
    log("=" * 60)
    log("TEST: Acceso a Configuraciones /config", "TEST")
    log("=" * 60)
    
    modules = ["wan", "vlans", "firewall", "nat", "dmz", "tagging", "ebtables"]
    
    results = {}
    for module in modules:
        file_path = f"/config/{module}/{module}.json"
        try:
            response = session.get(
                urljoin(BASE_URL, file_path),
                timeout=5
            )
            if response.status_code == 200:
                log(f"✅ {file_path}")
                results[module] = True
            else:
                log(f"❌ {file_path} - Status {response.status_code}")
                results[module] = False
        except Exception as e:
            log(f"❌ {file_path} - Error: {str(e)[:50]}")
            results[module] = False
    
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    log(f"\nTotal: {passed}/{total} configuraciones accesibles")
    return passed == total

def test_protected_access():
    """Probar que acceso sin autenticación redirige a login"""
    log("")
    log("=" * 60)
    log("TEST: Protección de Acceso (sin autenticación)", "TEST")
    log("=" * 60)
    
    # Crear session sin autenticación
    unauth_session = requests.Session()
    
    test_paths = [
        "/web/index.html",
        "/web/wan/index.html",
        "/config/wan/wan.json",
    ]
    
    results = {}
    for path in test_paths:
        try:
            response = unauth_session.get(
                urljoin(BASE_URL, path),
                timeout=5,
                allow_redirects=False
            )
            # Esperamos 307 redirect a /login
            if response.status_code == 307:
                location = response.headers.get("location", "")
                if location == "/login":
                    log(f"✅ {path} - Redirigido a /login (protegido)")
                    results[path] = True
                else:
                    log(f"⚠️  {path} - Redirigido a {location}")
                    results[path] = False
            else:
                log(f"❌ {path} - Status {response.status_code} (debería ser 307)")
                results[path] = False
        except Exception as e:
            log(f"❌ {path} - Error: {str(e)[:50]}")
            results[path] = False
    
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    log(f"\nTotal: {passed}/{total} rutas correctamente protegidas")
    return passed == total

def main():
    """Ejecutar todas las pruebas"""
    log("")
    log(f"Iniciando pruebas de endpoints /web contra {BASE_URL}")
    log("")
    
    # 1. Login
    if not test_login():
        log("\n❌ No se pudo autenticar. Abortando.", "ERROR")
        return 1
    
    # 2. Archivos web estáticos
    web_files_ok = test_web_files()
    
    # 3. Archivos por módulo
    module_files_ok = test_module_web_files()
    
    # 4. Configuraciones
    config_ok = test_config_api()
    
    # 5. Protección de acceso
    protected_ok = test_protected_access()
    
    # RESUMEN
    log("")
    log("=" * 60)
    log("RESUMEN FINAL", "SUMMARY")
    log("=" * 60)
    log(f"✅ Autenticación: OK")
    log(f"{'✅' if web_files_ok else '❌'} Archivos estáticos: {'OK' if web_files_ok else 'FALLOS'}")
    log(f"{'✅' if module_files_ok else '❌'} Archivos por módulo: {'OK' if module_files_ok else 'FALLOS'}")
    log(f"{'✅' if config_ok else '❌'} Acceso a configuraciones: {'OK' if config_ok else 'FALLOS'}")
    log(f"{'✅' if protected_ok else '❌'} Protección de acceso: {'OK' if protected_ok else 'FALLOS'}")
    
    all_ok = web_files_ok and module_files_ok and config_ok and protected_ok
    log("")
    log(f"{'✅ TODAS LAS PRUEBAS PASADAS' if all_ok else '❌ ALGUNAS PRUEBAS FALLARON'}")
    
    return 0 if all_ok else 1

if __name__ == "__main__":
    sys.exit(main())
