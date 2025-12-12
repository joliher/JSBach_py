#!/usr/bin/env python3

import os
import shutil
import subprocess
import sys
import json

# Códigos ANSI
BLUE = "\033[94m"
YELLOW = "\033[93m"
RED = "\033[91m"
GREEN = "\033[92m"
RESET = "\033[0m"

# -----------------------------
# Helper functions
# -----------------------------

def run(cmd):
    """Run a command and show it."""
    print(f"{BLUE}[CMD] {RESET}{cmd}")
    result = subprocess.run(cmd, shell=True)
    if result.returncode != 0:
        print(f"{RED}[ERROR] {RESET}El comando falló: {cmd}")
        sys.exit(result.returncode)

def ask(question, default=None):
    """Ask the user a yes/no or text question."""
    if default is not None:
        q = f"{question} [{default}]: "
    else:
        q = f"{question}: "
    answer = input(q).strip()
    return answer if answer else default

def ask_yes_no(question, default="s"):
    """
    Pregunta sí/no con formato [S/n] o [s/N].
    Retorna 's' o 'n'.
    """
    default = default.lower()
    if default not in ("s", "n"):
        raise ValueError("default debe ser 's' o 'n'")

    # Formato visual
    if default == "s":
        prompt = f"{question} [S/n]: "
    else:
        prompt = f"{question} [s/N]: "

    while True:
        answer = input(prompt).strip().lower()
        if answer == "":
            return default
        if answer in ("s", "n"):
            return answer

def ensure_root():
    if os.geteuid() != 0:
        print(f"{RED}[ERROR] {RESET}Debes ejecutar este script como root.")
        sys.exit(1)

# -----------------------------
# Installation steps
# -----------------------------

def install_dependencies():
    print("\n=== Instalando dependencias del sistema ===\n")

    commands = [
        "apt update -qq",  # -qq = menos salida
        "apt install -y python3 python3-pip python3-venv -qq"
    ]

    for cmd in commands:
        print(f"{BLUE}[INFO] {RESET}Ejecutando: {cmd.split()[0]} {cmd.split()[1]} ...")
        result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode != 0:
            print(f"{RED}[ERROR] {RESET}Falló el comando: {cmd}")
            print("Salida de error:")
            print(result.stderr.strip())
            sys.exit(result.returncode)


def prepare_directory(target_path):
    print("\n=== Preparando directorio del proyecto ===\n")

    # Ruta real del script (no el cwd)
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

    if not os.path.exists(target_path):
        print(f"{BLUE}[INFO] {RESET}Creando directorio {target_path}")
        os.makedirs(target_path)

    # Copiar backend
    backend_src = os.path.join(BASE_DIR, "..", "backend.py")
    backend_dst = os.path.join(target_path, "backend.py")

    if os.path.exists(backend_src):
        print(f"{BLUE}[INFO] {RESET}Copiando backend.py al directorio destino")
        shutil.copy2(backend_src, backend_dst)
    else:
        print(f"{YELLOW}[WARN] {RESET}backend.py no encontrado")

    # Copiar estáticos
    static_src = os.path.join(BASE_DIR, "..", "static")
    static_dst = os.path.join(target_path, "static")

    if os.path.exists(static_src):
        print(f"{BLUE}[INFO] {RESET}Copiando carpeta static/")
        if os.path.exists(static_dst):
            shutil.rmtree(static_dst)
        shutil.copytree(static_src, static_dst)
    else:
        print(f"{YELLOW}[WARN] {RESET}No existe carpeta static/")

def create_venv(target_path):
    print("\n=== Configurando entorno virtual ===\n")
    venv_path = os.path.join(target_path, "venv")

    # Crear venv sin mostrar output
    result = subprocess.run(f"python3 -m venv {venv_path}", shell=True,
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        print(f"{RED}[ERROR]{RESET} Falló al crear el entorno virtual.")
        print(result.stderr.strip())
        sys.exit(result.returncode)

    # Instalar dependencias sin mostrar output
    result = subprocess.run(f"{venv_path}/bin/pip install fastapi uvicorn", shell=True,
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        print(f"{RED}[ERROR]{RESET} Falló al instalar paquetes en el entorno virtual.")
        print(result.stderr.strip())
        sys.exit(result.returncode)

    print(f"{GREEN}[OK]{RESET} Entorno virtual configurado correctamente.")
    return venv_path

def create_systemd_service(target_path, venv_path):
    print("\n=== Creando servicio systemd ===\n")

    service_content = f"""
[Unit]
Description=Router JSBach Service
After=network.target

[Service]
User=root
WorkingDirectory={target_path}
ExecStart={venv_path}/bin/uvicorn backend:app --host 0.0.0.0 --port 8080
Restart=always

[Install]
WantedBy=multi-user.target
"""

    service_path = "/etc/systemd/system/router-JSBach.service"

    with open(service_path, "w") as f:
        f.write(service_content)

    # Comandos systemctl silenciosos
    systemctl_cmds = [
        "systemctl daemon-reload",
        "systemctl enable router-JSBach",
        "systemctl restart router-JSBach"
    ]

    for cmd in systemctl_cmds:
        result = subprocess.run(cmd, shell=True,
                                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        if result.returncode != 0:
            print(f"{RED}[ERROR]{RESET} Falló el comando: {cmd}")
            print(result.stderr.strip())
            sys.exit(result.returncode)

    print(f"{GREEN}[OK]{RESET} Servicio systemd creado y en ejecución.")

# -----------------------------
# Main installer logic
# -----------------------------

def main():
    ensure_root()

    print("\n====================================")
    print("   Instalador del Router (install.py)")
    print("====================================\n")

    # Preguntar ruta de instalación
    target_path = ask("Ruta de instalación del proyecto", "/opt/JSBach")

    # Instalar dependencias
    install_dependencies()

    # Preparar directorio del proyecto
    prepare_directory(target_path)

    # Crear entorno virtual
    create_env = ask_yes_no("¿Crear entorno virtual Python?", "s")
    if create_env.lower() == "s":
        venv_path = create_venv(target_path)
    else:
        venv_path = None

    # Crear servicio systemd
    create_service = ask_yes_no("¿Crear servicio systemd para el backend?", "s")
    if create_service.lower() == "s":
        if not venv_path:
            print(f"{RED}[ERROR] {RESET}No puedes crear el servicio si no instalaste el entorno virtual.")
            sys.exit(1)
        create_systemd_service(target_path, venv_path)

    print("\n=== Instalación completada con éxito ===\n")
    print(f"Proyecto instalado en: {BLUE}{target_path}")
    print(f"{RESET}Puedes iniciar tu backend con: {GREEN}systemctl start router-JSBach")


if __name__ == "__main__":
    main()

