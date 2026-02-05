#!/usr/bin/env python3
import sys
import os
import json

# Añadir el path base al sys.path para poder importar app
sys.path.append('/opt/JSBach_V4.0')

from app.core import expect

def test_case(name, params):
    print(f"\n--- TEST: {name} ---")
    print(f"INPUT: {json.dumps(params, indent=2)}")
    success, message = expect.config(params)
    print(f"RESULT: {'✅ SUCCESS' if success else '❌ FAIL'}")
    print(f"MESSAGE:\n{message}")

# 1. Éxito (Modo Simulación / Dry Run)
test_case("Caso de Éxito Normal", {
    "ip": "192.168.1.100",
    "profile": "cisco_ios",
    "actions": "hostname:SwitchCore / ports:1-5,vlan:10,mode:access",
    "dry_run": True
})

# 2. Fallo: Parámetro duplicado (Bypass frontend)
test_case("Bypass Frontend: Parámetros duplicados", {
    "ip": "192.168.1.100",
    "profile": "cisco_ios",
    "actions": "hostname:S1,hostname:S2",
    "dry_run": True
})

# 3. Fallo: TAG y UNTAG a la vez (Bypass frontend)
test_case("Bypass Frontend: TAG/UNTAG simultáneo", {
    "ip": "192.168.1.100",
    "profile": "cisco_ios",
    "actions": "ports:1,tag:10,untag:20",
    "dry_run": True
})

# 4. Fallo: Campo no válido para el perfil
test_case("Campo no válido", {
    "ip": "192.168.1.100",
    "profile": "cisco_ios",
    "actions": "parametro_inexistente:valor",
    "dry_run": True
})

# 5. Éxito: Sanitización de entrada maliciosa
test_case("Sanitización de Inyección", {
    "ip": "192.168.1.100",
    "profile": "cisco_ios",
    "actions": "hostname:Switch; rm -rf /",
    "dry_run": True
})

# 6. Fallo: IP Inválida
test_case("IP Inválida", {
    "ip": "999.999.999.999",
    "profile": "cisco_ios",
    "actions": "hostname:Test",
    "dry_run": True
})

# 7. Fallo: Puerto fuera de rango
test_case("Puerto fuera de rango", {
    "ip": "192.168.1.100",
    "profile": "cisco_ios",
    "actions": "ports:100,vlan:10",
    "dry_run": True
})
