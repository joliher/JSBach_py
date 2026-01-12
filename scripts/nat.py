#!/usr/bin/env python3
import os
import sys
import subprocess
import json

# --------------------------------------------------
# Configuración dinámica
# --------------------------------------------------
CONFIG_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "config",
    "nat.json"
)

# --------------------------------------------------
# Utilidades
# --------------------------------------------------
def cargar_config():
    """Cargar o inicializar configuración NAT"""
    if not os.path.exists(CONFIG_FILE):
        os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
        # Configuración por defecto
        config_default = {"interfaz": "", "status": 0}
        with open(CONFIG_FILE, "w") as f:
            json.dump(config_default, f, indent=4)
        return config_default

    try:
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    except Exception as e:
        print(f"Error leyendo configuración NAT: {e}", file=sys.stderr)
        return None

def guardar_config(config):
    try:
        os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
        with open(CONFIG_FILE, "w") as f:
            json.dump(config, f, indent=4)
    except Exception as e:
        print(f"Error guardando configuración NAT: {e}", file=sys.stderr)

# --------------------------------------------------
# Acciones NAT
# --------------------------------------------------
def nat_start():
    config = cargar_config()
    if not config:
        sys.exit(1)

    interfaz = config.get("interfaz")
    if not interfaz:
        print("Error: No hay interfaz definida en la configuración NAT", file=sys.stderr)
        sys.exit(1)

    # Comprobar si NAT ya está activo
    cmd = ["iptables", "-t", "nat", "-C", "POSTROUTING", "-o", interfaz, "-j", "MASQUERADE"]
    if subprocess.run(cmd, capture_output=True).returncode == 0:
        print(f"El NAT ya está activado en la interfaz {interfaz}")
        sys.exit(0)

    print("Activando NAT...")
    try:
        # Activar IP forwarding
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1")
        # Añadir regla NAT
        subprocess.run(
            ["iptables", "-t", "nat", "-A", "POSTROUTING", "-o", interfaz, "-j", "MASQUERADE"],
            check=True
        )
        # Actualizar estado en JSON
        config["status"] = 1
        guardar_config(config)
        print(f"NAT activado en la interfaz {interfaz}")
    except Exception as e:
        print(f"Error activando NAT: {e}", file=sys.stderr)
        sys.exit(1)

def nat_stop():
    config = cargar_config()
    if not config:
        sys.exit(1)

    interfaz = config.get("interfaz")
    if not interfaz:
        print("Error: No hay interfaz definida en la configuración NAT", file=sys.stderr)
        sys.exit(1)

    print("Desactivando NAT...")
    try:
        # Desactivar IP forwarding
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("0")
        # Eliminar regla NAT (ignorar error si no existía)
        subprocess.run(
            ["iptables", "-t", "nat", "-D", "POSTROUTING", "-o", interfaz, "-j", "MASQUERADE"],
            check=False
        )
        # Actualizar estado en JSON
        config["status"] = 0
        guardar_config(config)
        print(f"NAT desactivado en la interfaz {interfaz}")
    except Exception as e:
        print(f"Error desactivando NAT: {e}", file=sys.stderr)
        sys.exit(1)

def nat_status():
    config = cargar_config()
    if not config:
        sys.exit(1)

    interfaz = config.get("interfaz")
    if not interfaz:
        print("Error: No hay interfaz definida en la configuración NAT", file=sys.stderr)
        sys.exit(1)

    try:
        ip_forward = open("/proc/sys/net/ipv4/ip_forward").read().strip()
        cmd = ["iptables", "-t", "nat", "-C", "POSTROUTING", "-o", interfaz, "-j", "MASQUERADE"]
        result = subprocess.run(cmd, capture_output=True)
        if ip_forward == "1" and result.returncode == 0:
            print(f"NAT ACTIVADO en la interfaz {interfaz}")
        else:
            print(f"NAT DESACTIVADO en la interfaz {interfaz}")
    except Exception as e:
        print(f"Error verificando NAT: {e}", file=sys.stderr)
        sys.exit(1)

def nat_config(params):
    """Permite definir la interfaz NAT desde parámetros"""
    interfaz = params.get("interfaz")
    if not interfaz:
        print("Error: Falta el parámetro 'interfaz' para la configuración NAT", file=sys.stderr)
        sys.exit(1)

    config = {"interfaz": interfaz, "status": 0}
    guardar_config(config)
    print(f"Configuración NAT guardada correctamente. Interfaz: {interfaz}")

# --------------------------------------------------
# Main
# --------------------------------------------------
if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Necesitas ser root")
        sys.exit(1)

    if len(sys.argv) < 2:
        print("Uso: nat.py --[start|stop|status|config] [--interfaz=INTERFAZ]")
        sys.exit(1)

    accion = sys.argv[1]

    if accion == "--start":
        nat_start()
    elif accion == "--stop":
        nat_stop()
    elif accion == "--status":
        nat_status()
    elif accion == "--config":
        # Leer parámetros --interfaz=xxx
        params = {}
        for arg in sys.argv[2:]:
            if arg.startswith("--"):
                key, sep, value = arg[2:].partition("=")
                if sep:
                    params[key] = value
        nat_config(params)
    else:
        print("Argumento no válido.")
        print("Uso: nat.py --[start|stop|status|config]")
        sys.exit(1)
