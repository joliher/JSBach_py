#!/usr/bin/env python3
import sys
import subprocess
import json
import os

CONFIG_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config", "wan.json")

def load_config():
    if not os.path.exists(CONFIG_FILE):
        return None
    with open(CONFIG_FILE, "r") as f:
        return json.load(f)

def wan_start():
    config = load_config()
    if not config:
        print("Error: No hay configuración WAN", file=sys.stderr)
        sys.exit(4)

    iface = config.get("interface")
    mode = config.get("mode")

    try:
        subprocess.run(["ip", "link", "show", iface], check=True, capture_output=True)
    except subprocess.CalledProcessError:
        print(f"Error: La interfaz {iface} no existe", file=sys.stderr)
        sys.exit(1)

    if mode == "dhcp":
        try:
            subprocess.run(["dhcpcd", iface], check=True, capture_output=True)
        except subprocess.CalledProcessError as e:
            print(f"Error DHCP: {e}", file=sys.stderr)
            sys.exit(2)
    elif mode == "manual":
        ip = config.get("ip")
        mask = config.get("mask")
        gateway = config.get("gateway")
        try:
            subprocess.run(["ip", "a", "add", f"{ip}/{mask}", "dev", iface], check=True)
            subprocess.run(["ip", "r", "add", "default", "via", gateway], check=True)
            subprocess.run(["ip", "link", "set", "dev", iface, "up"], check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error IP manual: {e}", file=sys.stderr)
            sys.exit(3)
    else:
        print(f"Error: Modo desconocido {mode}", file=sys.stderr)
        sys.exit(4)

    print("WAN iniciada correctamente")
    sys.exit(0)

def wan_stop():
    config = load_config()
    if not config:
        print("Error: No hay configuración WAN", file=sys.stderr)
        sys.exit(4)

    iface = config.get("interface")

    try:
        subprocess.run(["ip", "link", "set", "dev", iface, "down"], check=True)
        subprocess.run(["ip", "a", "flush", "dev", iface], check=True)
        subprocess.run(["ip", "r", "flush", "dev", iface], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error al detener WAN: {e}", file=sys.stderr)
        sys.exit(1)

    print("WAN detenida correctamente")
    sys.exit(0)

def wan_status():
    config = load_config()
    if not config:
        print("Error: No hay configuración WAN", file=sys.stderr)
        sys.exit(4)

    iface = config.get("interface")

    try:
        ip_info = subprocess.run(["ip", "a", "show", iface], check=True, capture_output=True, text=True)
        route_info = subprocess.run(["ip", "r", "show"], check=True, capture_output=True, text=True)
        print(f"Estado de la interfaz {iface}:\n{ip_info.stdout}\nRutas:\n{route_info.stdout}")
    except subprocess.CalledProcessError as e:
        print(f"Error obteniendo estado: {e}", file=sys.stderr)
        sys.exit(1)

    sys.exit(0)

def wan_restart():
    wan_stop()
    wan_start()

def wan_config(params):
    required = ["mode", "interface"]
    for r in required:
        if r not in params or not params[r]:
            print(f"Error: Falta el parámetro {r}", file=sys.stderr)
            sys.exit(4)

    if params["mode"] == "manual":
        manual_required = ["ip", "mask", "gateway", "dns"]
        for r in manual_required:
            if r not in params or not params[r]:
                print(f"Error: Falta el parámetro {r} para modo manual", file=sys.stderr)
                sys.exit(4)

    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    with open(CONFIG_FILE, "w") as f:
        json.dump(params, f, indent=4)
    print("Configuración guardada correctamente")
    sys.exit(0)

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Script WAN")
    parser.add_argument("--action", choices=["start", "stop", "restart", "status", "config"], required=True)
    args, unknown = parser.parse_known_args()

    if args.action == "start":
        wan_start()
    elif args.action == "stop":
        wan_stop()
    elif args.action == "restart":
        wan_restart()
    elif args.action == "status":
        wan_status()
    elif args.action == "config":
        # Convertir unknown args a diccionario
        config_params = {}
        for arg in unknown:
            if arg.startswith("--"):
                key_val = arg[2:].split("=", 1)
                if len(key_val) == 2:
                    config_params[key_val[0]] = key_val[1]
        wan_config(config_params)
