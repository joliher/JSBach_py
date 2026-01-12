#!/usr/bin/env python3
import os
import sys
import subprocess
import json

# --------------------------------------------------
# Configuración dinámica
# --------------------------------------------------
CONFIG_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "config",
    "bridge"
)
VLANS_FILE = os.path.join(CONFIG_DIR, "vlans.json")
BRIDGE_FILE = os.path.join(CONFIG_DIR, "bridge.json")

# --------------------------------------------------
# Utilidades
# --------------------------------------------------

def bridge_exists():
    return os.path.exists("/sys/class/net/br0")

def ensure_root():
    if os.geteuid() != 0:
        print("Necesitas ser root")
        sys.exit(1)

def load_json(path, default):
    """Cargar JSON o inicializar con default + status"""
    if not os.path.exists(path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        default_with_status = default.copy()
        default_with_status["status"] = 0
        with open(path, "w") as f:
            json.dump(default_with_status, f, indent=4)
        return default_with_status
    try:
        with open(path, "r") as f:
            data = json.load(f)
            if "status" not in data:
                data["status"] = 0
            return data
    except Exception as e:
        print(f"Error leyendo {path}: {e}", file=sys.stderr)
        default["status"] = 0
        return default

def save_json(path, data):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        print(f"Error guardando {path}: {e}", file=sys.stderr)

def run_cmd(cmd, ignore_error=False):
    try:
        subprocess.run(cmd, check=not ignore_error)
    except subprocess.CalledProcessError:
        if not ignore_error:
            print(f"Error ejecutando: {' '.join(cmd)}", file=sys.stderr)

# --------------------------------------------------
# Acciones Bridge
# --------------------------------------------------
def bridge_start():
    ensure_root()

    vlans = load_json(VLANS_FILE, {"vlans": []})
    bridges = load_json(BRIDGE_FILE, {"interfaces": []})

    # Crear br0 si no existe
    if not os.path.exists("/sys/class/net/br0"):
        run_cmd(
            ["ip", "link", "add", "name", "br0", "type", "bridge", "vlan_filtering", "1"],
            ignore_error=True
        )

    run_cmd(["ip", "link", "set", "br0", "up"])
    print("br0 CREADA")

    # Crear subinterfaces VLAN y asignar IPs
    for vlan in vlans.get("vlans", []):
        vlan_id = str(vlan.get("id"))
        vlan_ip = vlan.get("ip")
        iface_name = f"br0.{vlan_id}"

        if not os.path.exists(f"/sys/class/net/{iface_name}"):
            run_cmd(
                ["ip", "link", "add", "link", "br0", "name", iface_name, "type", "vlan", "id", vlan_id],
                ignore_error=True
            )

        run_cmd(["ip", "link", "set", iface_name, "up"])

        if vlan_ip:
            run_cmd(
                ["ip", "addr", "add", vlan_ip, "dev", iface_name],
                ignore_error=True
            )
            print(f"Interfaz {iface_name} CREADA con IP {vlan_ip}")

    # Solo tocar VLAN 1 si hay interfaces físicas
    if bridges.get("interfaces"):
        run_cmd(
            ["bridge", "vlan", "del", "dev", "br0", "vid", "1", "pvid", "untagged"],
            ignore_error=True
        )
    else:
        print("Aviso: no hay interfaces físicas asociadas al bridge")

    # Configurar TAG / UNTAG en interfaces físicas
    for iface in bridges.get("interfaces", []):
        name = iface.get("name")
        vlan_untag = iface.get("vlan_untag")
        vlan_tag = iface.get("vlan_tag")

        if not name:
            continue

        run_cmd(["ip", "link", "set", name, "master", "br0"], ignore_error=True)
        run_cmd(["ip", "link", "set", name, "up"], ignore_error=True)

        # Eliminar VLAN 1 por defecto en la interfaz
        run_cmd(
            ["bridge", "vlan", "del", "dev", name, "vid", "1", "pvid", "untagged"],
            ignore_error=True
        )

        # VLAN UNTAG
        if vlan_untag:
            run_cmd(
                ["bridge", "vlan", "add", "dev", name, "vid", str(vlan_untag), "pvid", "untagged"],
                ignore_error=True
            )
            run_cmd(
                ["bridge", "vlan", "add", "dev", "br0", "vid", str(vlan_untag), "self"],
                ignore_error=True
            )

        # VLAN TAG
        if vlan_tag:
            for vid in map(str, str(vlan_tag).split(",")):
                run_cmd(
                    ["bridge", "vlan", "add", "dev", name, "vid", vid],
                    ignore_error=True
                )
                run_cmd(
                    ["bridge", "vlan", "add", "dev", "br0", "vid", vid, "self"],
                    ignore_error=True
                )

    # Actualizar estado en JSON
    vlans["status"] = 1
    bridges["status"] = 1
    save_json(VLANS_FILE, vlans)
    save_json(BRIDGE_FILE, bridges)

    print("TAG/UNTAG CONFIGURADO")
    print("Bridge ACTIVADO")

def bridge_stop():
    ensure_root()

    vlans = load_json(VLANS_FILE, {"vlans": [], "status": 0})
    bridges = load_json(BRIDGE_FILE, {"interfaces": [], "status": 0})

    if bridge_exists():
        run_cmd(["ip", "link", "set", "br0", "down"], ignore_error=True)
        run_cmd(["ip", "link", "del", "dev", "br0"], ignore_error=True)
        print("Bridge DETENIDO")
    else:
        print("Bridge ya estaba DETENIDO")

    # Actualizar estado en JSON aunque no existiera
    vlans["status"] = 0
    bridges["status"] = 0
    save_json(VLANS_FILE, vlans)
    save_json(BRIDGE_FILE, bridges)

def bridge_restart():
    print("Reiniciando bridge...")

    if bridge_exists():
        bridge_stop()
    else:
        print("Bridge ya estaba DETENIDO")

    bridge_start()
    print("Bridge REINICIADO")

import subprocess

def bridge_status():
    vlans = load_json(VLANS_FILE, {"vlans": []})
    bridges = load_json(BRIDGE_FILE, {"interfaces": []})

    active = vlans.get("status", 0) == 1 and bridges.get("status", 0) == 1

    # ----- ESTADO -----
    if active:
        print("Bridge ACTIVO")
    else:
        print("Bridge INACTIVO")

    # ----- VLANS -----
    print("\nVLANS CONFIGURADAS:")
    try:
        result = subprocess.run(
            ["ip", "-br", "addr", "show", "type", "vlan"],
            capture_output=True,
            text=True,
            check=True
        )
        if result.stdout.strip():
            print(result.stdout.rstrip())
        else:
            print("(sin datos)")
    except subprocess.CalledProcessError as e:
        print("Error al mostrar el estado de las VLANS")
        print(e.stderr or str(e))

    # ----- INTERFACES -----
    print("\nINTERFACES CONFIGURADAS:")
    try:
        result = subprocess.run(
            ["bridge", "vlan", "show"],
            capture_output=True,
            text=True,
            check=True
        )
        if result.stdout.strip():
            print(result.stdout.rstrip())
        else:
            print("(sin datos)")
    except subprocess.CalledProcessError as e:
        print("Error al mostrar el estado del BRIDGE")
        print(e.stderr or str(e))

def bridge_config(params):
    vlans = load_json(VLANS_FILE, {"vlans":[]})
    bridges = load_json(BRIDGE_FILE, {"interfaces":[]})

    action = params.get("action")
    section = params.get("section")  # "vlans" o "bridge"

    if action == "show":
        if section == "vlans":
            for v in vlans["vlans"]:
                print(v)
        elif section == "bridge":
            for b in bridges["interfaces"]:
                print(b)
        else:
            print("Uso: --config show [vlans|bridge]")
    elif action == "save":
        if section == "vlans":
            required = ["id", "name", "ip"]
            if not all(k in params for k in required):
                print("Faltan parámetros para guardar VLAN")
                return
            vlans["vlans"] = [v for v in vlans["vlans"] if str(v.get("id")) != str(params["id"])]
            vlans["vlans"].append({
                "id": int(params["id"]),
                "name": params["name"],
                "ip": params.get("ip")
            })
            save_json(VLANS_FILE, vlans)
            print("VLAN guardada")
        elif section == "bridge":
            required = ["name"]
            if not all(k in params for k in required):
                print("Faltan parámetros para guardar interface")
                return

            # Normalizar campos vacíos
            vlan_untag = params.get("vlan_untag") or ""
            vlan_tag   = params.get("vlan_tag") or ""

            # Eliminar si ya existía la interface
            bridges["interfaces"] = [b for b in bridges["interfaces"] if b.get("name") != params["name"]]

            # Guardar la interface
            bridges["interfaces"].append({
                "name": params["name"],
                "vlan_untag": vlan_untag,
                "vlan_tag": vlan_tag
            })

            save_json(BRIDGE_FILE, bridges)
            print("Interface guardada")
        else:
            print("Uso: --config save [vlans|bridge]")
    elif action == "del":
        if section == "vlans":
            vid = params.get("id")
            if not vid:
                print("Falta id para eliminar VLAN")
                return
            vlans["vlans"] = [v for v in vlans["vlans"] if str(v.get("id")) != str(vid)]
            save_json(VLANS_FILE, vlans)
            print(f"VLAN {vid} eliminada")
        elif section == "bridge":
            name = params.get("name")
            if not name:
                print("Falta name para eliminar interface")
                return
            bridges["interfaces"] = [b for b in bridges["interfaces"] if b.get("name") != name]
            save_json(BRIDGE_FILE, bridges)
            print(f"Interface {name} eliminada")
        else:
            print("Uso: --config del [vlans|bridge]")
    else:
        print("Uso: --config [show|save|del]")

# --------------------------------------------------
# Main
# --------------------------------------------------
if __name__ == "__main__":
    ensure_root()
    if len(sys.argv) < 2:
        print("Uso: bridge.py --[start|stop|restart|status|config] [parámetros]")
        sys.exit(1)

    action = sys.argv[1]

    if action == "--start":
        bridge_start()
    elif action == "--stop":
        bridge_stop()
    elif action == "--restart":
        bridge_restart()
    elif action == "--status":
        bridge_status()
    elif action == "--config":
        params = {}
        for arg in sys.argv[2:]:
            if arg.startswith("--"):
                key, sep, value = arg[2:].partition("=")
                if sep:
                    params[key] = value
        bridge_config(params)
    else:
        print("Argumento no válido")
        print("Uso: bridge.py --[start|stop|restart|status|config]")
        sys.exit(1)