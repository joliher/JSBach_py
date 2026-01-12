#!/usr/bin/env python3
import sys
import subprocess
import json
import os

# -----------------------------
# Verificar si es root
# -----------------------------
if os.geteuid() != 0:
    print("Necesitas ser root")
    sys.exit(1)

CONFIG_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "config",
    "wan.json"
)

# --------------------------------------------------
# Utilidades
# --------------------------------------------------

def update_status_json(estado):
    """
    Actualiza el campo 'status' en el archivo de configuración WAN.
    estado: 0 = INACTIVO, 1 = ACTIVO
    """
    config = load_config()
    if config is None:
        config = {}  # Si no existe config, crear diccionario vacío

    config["status"] = estado

    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump(config, f, indent=4)
    except Exception as e:
        print(f"No se pudo actualizar el status en el JSON: {e}", file=sys.stderr)

def load_config():
    if not os.path.exists(CONFIG_FILE):
        print("Error: Archivo de configuración WAN no encontrado", file=sys.stderr)
        return None

    try:
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    except json.JSONDecodeError:
        print("Error: El archivo de configuración WAN está corrupto", file=sys.stderr)
        return None
    except Exception as e:
        print(f"Error leyendo configuración WAN: {e}", file=sys.stderr)
        return None


# --------------------------------------------------
# Acciones WAN
# --------------------------------------------------

def wan_start():
    config = load_config()
    if not config:
        sys.exit(4)

    iface = config.get("interface")
    mode = config.get("mode")

    if not iface or not mode:
        print("Error: Configuración WAN incompleta", file=sys.stderr)
        sys.exit(4)

    try:
        subprocess.run(
            ["ip", "link", "show", iface],
            check=True,
            capture_output=True,
            text=True
        )
    except subprocess.CalledProcessError:
        print(f"Error: La interfaz {iface} no existe", file=sys.stderr)
        sys.exit(1)

    if mode == "dhcp":
        try:
            subprocess.run(
                ["dhcpcd", iface],
                check=True,
                capture_output=True,
                text=True
            )
            print("DHCP configurado correctamente")
            update_status_json(1)
        except subprocess.CalledProcessError as e:
            print(f"Error DHCP: {e}", file=sys.stderr)
            sys.exit(2)

    elif mode == "manual":
        ip = config.get("ip")
        mask = config.get("mask")
        gateway = config.get("gateway")
        dns = config.get("dns")

        # Procesar DNS
        if dns:
            if isinstance(dns, str):
                dns_list = [d.strip() for d in dns.split(",") if d.strip()]
            elif isinstance(dns, list):
                dns_list = dns
            else:
                dns_list = []
        else:
            dns_list = []

        # Limpiar configuración previa
        try:
            subprocess.run(["ip", "a", "flush", "dev", iface], check=True)
        except subprocess.CalledProcessError:
            print(f"No se pudo borrar la configuración de {iface}")

        # Asignar IP
        try:
            subprocess.run(
                ["ip", "a", "add", f"{ip}/{mask}", "dev", iface],
                check=True,
                capture_output=True,
                text=True
            )
        except subprocess.CalledProcessError as e:
            stderr = getattr(e, "stderr", "") or ""
            if "File exists" in stderr or "RTNETLINK answers: File exists" in stderr:
                print(f"La IP {ip}/{mask} ya estaba asignada a {iface}, ignorando.")
            else:
                print(
                    f"No se ha podido asignar la IP {ip}/{mask} a {iface}: {e}",
                    file=sys.stderr
                )
                sys.exit(3)

        # Levantar interfaz
        try:
            subprocess.run(["ip", "l", "set", "dev", iface, "up"], check=True)
        except subprocess.CalledProcessError:
            print(f"No se ha podido levantar la interfaz {iface}")

        # Ruta por defecto
        try:
            subprocess.run(
                ["ip", "r", "add", "default", "via", gateway, "dev", iface],
                check=True,
                capture_output=True,
                text=True
            )
        except subprocess.CalledProcessError as e:
            stderr = getattr(e, "stderr", "") or ""
            if "File exists" in stderr or "RTNETLINK answers: File exists" in stderr:
                print("Ya existe una ruta por defecto. Imposible asignar una nueva.")

        # ----------------------------
        # DNS PERMANENTE
        # ----------------------------
        if dns_list:
            try:
                # systemd-resolved (persistente)
                subprocess.run(["resolvectl", "revert", iface], check=False)
                subprocess.run(
                    ["resolvectl", "dns", iface] + dns_list,
                    check=True
                )
                print(f"DNS configurados vía systemd-resolved: {', '.join(dns_list)}")

            except FileNotFoundError:
                # Fallback clásico: resolv.conf
                resolv_conf = "/etc/resolv.conf"
                backup_file = "/etc/resolv.conf.wan.bak"
                try:
                    if not os.path.exists(backup_file):
                        subprocess.run(["cp", resolv_conf, backup_file], check=True)

                    with open(resolv_conf, "w") as f:
                        for d in dns_list:
                            f.write(f"nameserver {d}\n")

                    print(f"DNS configurados permanentemente: {', '.join(dns_list)}")
                except Exception as e:
                    print(
                        f"No se pudo configurar DNS permanentemente: {e}",
                        file=sys.stderr
                    )

        print("WAN iniciada correctamente")
        update_status_json(1)
        sys.exit(0)

    else:
        print(f"Error: Modo desconocido '{mode}'", file=sys.stderr)
        sys.exit(4) 

def wan_stop():
    config = load_config()
    if not config:
        sys.exit(4)

    iface = config.get("interface")
    if not iface:
        print("Error: Interfaz WAN no definida", file=sys.stderr)
        sys.exit(4)

    # ----------------------------
    # Limpiar DNS
    # ----------------------------
    try:
        # Intentar revertir cambios de systemd-resolved
        subprocess.run(["resolvectl", "revert", iface], check=False)
        print(f"DNS revertidos para {iface} vía systemd-resolved")
    except FileNotFoundError:
        # Fallback clásico
        resolv_conf = "/etc/resolv.conf"
        backup_file = "/etc/resolv.conf.wan.bak"
        try:
            if os.path.exists(backup_file):
                subprocess.run(["cp", backup_file, resolv_conf], check=True)
                print(f"DNS restaurados desde backup {backup_file}")
            else:
                # Si no hay backup, limpiar resolv.conf
                with open(resolv_conf, "w") as f:
                    f.write("")
                print(f"DNS eliminados de {resolv_conf}")
        except Exception as e:
            print(f"No se pudo limpiar DNS: {e}", file=sys.stderr)

    # ----------------------------
    # Limpiar IP y rutas
    # ----------------------------
    try:
        subprocess.run(
            ["ip", "link", "set", "dev", iface, "down"],
            check=True,
            capture_output=True,
            text=True
        )
        subprocess.run(
            ["ip", "a", "flush", "dev", iface],
            check=True,
            capture_output=True,
            text=True
        )
        subprocess.run(
            ["ip", "r", "flush", "dev", iface],
            check=True,
            capture_output=True,
            text=True
        )
        try:
            subprocess.run(
                ["dhcpcd", "-k", iface],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                text=True
            )
        except subprocess.CalledProcessError:
            pass

    except subprocess.CalledProcessError as e:
        print(f"Error al detener WAN: {e}", file=sys.stderr)
        sys.exit(1)

    print("WAN detenida correctamente")
    update_status_json(0)

def wan_status():
    config = load_config()
    if not config:
        sys.exit(4)

    iface = config.get("interface")
    if not iface:
        print("Error: Interfaz WAN no definida", file=sys.stderr)
        sys.exit(4)

    try:
        ip_info = subprocess.run(
            ["ip", "a", "show", iface],
            check=True,
            capture_output=True,
            text=True
        )
        route_info = subprocess.run(
            ["ip", "r", "show"],
            check=True,
            capture_output=True,
            text=True
        )

        print(f"Estado de la interfaz {iface}:\n")
        print(ip_info.stdout.strip())
        print("\nRutas:\n")
        print(route_info.stdout.strip())

    except subprocess.CalledProcessError as e:
        print(f"Error obteniendo estado WAN: {e}", file=sys.stderr)
        sys.exit(1)

    sys.exit(0)


def wan_restart():
    wan_stop()
    wan_start()

def wan_config(params):
    required = ["mode", "interface"]
    for r in required:
        if not params.get(r):
            print(f"Error: Falta el parámetro '{r}'", file=sys.stderr)
            sys.exit(4)

    if params["mode"] == "manual":
        manual_required = ["ip", "mask", "gateway", "dns"]
        for r in manual_required:
            if not params.get(r):
                print(f"Error: Falta el parámetro '{r}' para modo manual", file=sys.stderr)
                sys.exit(4)

    try:
        os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
        with open(CONFIG_FILE, "w") as f:
            json.dump(params, f, indent=4)
    except Exception as e:
        print(f"Error guardando configuración WAN: {e}", file=sys.stderr)
        sys.exit(1)

    print("Configuración WAN guardada correctamente")
    sys.exit(0)


# --------------------------------------------------
# Main
# --------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Gestión WAN")
    parser.add_argument(
        "--action",
        choices=["start", "stop", "restart", "status", "config"],
        required=True
    )

    args, unknown = parser.parse_known_args()

    if args.action == "config":
        config_params = {}
        for arg in unknown:
            if arg.startswith("--"):
                key, sep, value = arg[2:].partition("=")
                if sep:
                    config_params[key] = value
        wan_config(config_params)

    elif args.action == "start":
        wan_start()
    elif args.action == "stop":
        wan_stop()
        sys.exit(0)
    elif args.action == "restart":
        wan_restart()
    elif args.action == "status":
        wan_status()
