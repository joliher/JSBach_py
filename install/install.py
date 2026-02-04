def create_cli_systemd_service(target_path, venv_path):
    info("Creando servicio systemd para CLI")
    cli_path = os.path.join(target_path, "app", "cli", "cli_server.py")
    service_content = f"""[Unit]
Description=JSBach V4.0 CLI Service
After=jsbach.service
Requires=jsbach.service

[Service]
Type=simple
User=jsbach
Group=jsbach
WorkingDirectory={target_path}
Environment=\"PATH={venv_path}/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"
ExecStart={venv_path}/bin/python3 {cli_path}
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"""
    service_path = "/etc/systemd/system/jsbach-cli.service"
    with open(service_path, "w") as f:
        f.write(service_content)

    cmds = [
        "systemctl daemon-reload",
        "systemctl enable jsbach-cli",
        "systemctl restart jsbach-cli"
    ]
    for c in cmds:
        result = subprocess.run(c, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        if result.returncode != 0:
            error(f"Fallo al ejecutar: {c}\n{result.stderr.strip()}")
    success("Servicio systemd CLI creado y en ejecución")
#!/usr/bin/env python3

import os
import shutil
import subprocess
import sys
import platform
import getpass
import json
import hashlib
from datetime import datetime

###############
#   Colores   #
###############
BLUE = "\033[94m"
YELLOW = "\033[93m"
RED = "\033[91m"
GREEN = "\033[92m"
RESET = "\033[0m"

###############
#   Mensajes  #
###############
def info(msg):
    print(f"{BLUE}[INFO]{RESET} {msg}")

def warn(msg):
    print(f"{YELLOW}[WARN]{RESET} {msg}")

def error(msg, exit_code=1):
    print(f"{RED}[ERROR]{RESET} {msg}")
    sys.exit(exit_code)

def success(msg):
    print(f"{GREEN}[OK]{RESET} {msg}")

def cmd(msg):
    print(f"{BLUE}[CMD]{RESET} {msg}")

############
#   Logs  #
############
def create_logs_directory(target_path):
    log_dir = os.path.join(target_path, "logs")
    if not os.path.exists(log_dir):
        info(f"Creando directorio de logs en {log_dir}")
        os.makedirs(log_dir)

    # Cambiar permisos a jsbach:jsbach con 755
    info(f"Cambiando permisos de {log_dir} a 755 y propietario a jsbach:jsbach")
    subprocess.run(f"chown jsbach:jsbach {log_dir}", shell=True)
    subprocess.run(f"chmod 755 {log_dir}", shell=True)
    success(f"Directorio de logs creado y permisos establecidos en {log_dir}")

############
#  Config  #
############
def create_config_directory(target_path):
    config_dir = os.path.join(target_path, "config")
    if not os.path.exists(config_dir):
        info(f"Creando directorio de config en {config_dir}")
        os.makedirs(config_dir)

    # Cambiar permisos a jsbach:jsbach con 755
    info(f"Cambiando permisos de {config_dir} a 755 y propietario a jsbach:jsbach")
    subprocess.run(f"chown jsbach:jsbach {config_dir}", shell=True)
    subprocess.run(f"chmod 755 {config_dir}", shell=True)
    success(f"Directorio de config creado y permisos establecidos en {config_dir}")

###############
#   QOL       #
###############
def ask(question, default=None):
    if default is not None:
        q = f"{question} [{default}]: "
    else:
        q = f"{question}: "
    answer = input(q).strip()
    return answer if answer else default

def ask_yes_no(question, default="s"):
    default = default.lower()
    if default not in ("s","n"):
        raise ValueError("default debe ser 's' o 'n'")
    prompt = f"{question} [{'S/n' if default=='s' else 's/N'}]: "
    while True:
        answer = input(prompt).strip().lower()
        if answer == "":
            return default
        if answer in ("s","n"):
            return answer

def ensure_root():
    if os.geteuid() != 0:
        error("Debes ejecutar este script como root.")

###############
#   Dependencias
###############
def install_dependencies():
    info("Instalando dependencias del sistema...")
    
    # Paquetes necesarios:
    # - python3, python3-pip, python3-venv: entorno Python
    # - iptables: reglas de firewall, NAT, DMZ
    # - iproute2: comandos ip y bridge para VLANs y routing
    # - ebtables: filtrado L2 para aislamiento de VLANs
    commands = [
        "apt update -qq",
        "apt install -y python3 python3-pip python3-venv iptables iproute2 ebtables -qq"
    ]
    for c in commands:
        cmd(c)
        result = subprocess.run(c, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode != 0:
            error(f"Falló el comando: {c}\n{result.stderr.strip()}")

###############
#   Usuarios
###############
def create_user(username="jsbach"):
    try:
        # Comprobar si el usuario existe
        subprocess.run(f"id -u {username}", shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        info(f"Usuario {username} ya existe")
    except subprocess.CalledProcessError:
        info(f"Creando usuario {username}")
        result = subprocess.run(f"useradd -m -s /bin/bash {username}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode != 0:
            error(f"No se pudo crear el usuario {username}: {result.stderr.strip()}")
        success(f"Usuario {username} creado correctamente")

###############
#   Proyecto
###############
DIRECTORY_WHITELIST = ["app", "web"]  # directorios de código fuente
FILE_WHITELIST = ["main.py"]  # archivos raíz necesarios

def prepare_directory(target_path):
    info(f"Preparando directorio del proyecto en {target_path}")
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    if not os.path.exists(target_path):
        info(f"Creando directorio {target_path}")
        os.makedirs(target_path)

    # Copiar directorios de código fuente
    for folder in DIRECTORY_WHITELIST:
        src = os.path.join(BASE_DIR, folder)
        dst = os.path.join(target_path, folder)
        if os.path.exists(src) and not os.path.exists(dst):
            info(f"Copiando {folder}/ ...")
            shutil.copytree(src, dst)
        else:
            if not os.path.exists(dst):
                warn(f"No existe carpeta {folder}/ para copiar")
    
    # Copiar archivos raíz necesarios
    for file in FILE_WHITELIST:
        src = os.path.join(BASE_DIR, file)
        dst = os.path.join(target_path, file)
        if os.path.exists(src) and not os.path.exists(dst):
            info(f"Copiando {file} ...")
            shutil.copy2(src, dst)
        elif not os.path.exists(src):
            warn(f"No existe archivo {file} para copiar")

###############
#   Entorno virtual
###############
def create_venv(target_path):
    info("Creando entorno virtual Python")
    venv_path = os.path.join(target_path, "venv")
    if os.path.exists(venv_path):
        info("Entorno virtual ya existe")
        return venv_path
    result = subprocess.run(f"python3 -m venv {venv_path}", shell=True,
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        error(f"Fallo al crear el entorno virtual: {result.stderr.strip()}")
    # Instalar paquetes
    result = subprocess.run(f"{venv_path}/bin/pip install fastapi[all] uvicorn requests", shell=True,
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        error(f"Fallo al instalar paquetes en el entorno virtual: {result.stderr.strip()}")
    success("Entorno virtual configurado correctamente")
    return venv_path

###############
#   Servicio systemd
###############
def set_directory_permissions(target_path):
    """Establecer permisos adecuados para directorios y archivos del proyecto."""
    info("Configurando permisos de directorios y archivos")
    
    # Cambiar owner de todo el proyecto a jsbach:jsbach
    subprocess.run(f"chown -R jsbach:jsbach {target_path}", shell=True)
    
    # Config: jsbach puede crear/modificar archivos (rwx para user, rx para group)
    config_dir = os.path.join(target_path, "config")
    if os.path.exists(config_dir):
        info(f"  Config: 750 (rwxr-x---) - jsbach puede crear/modificar")
        subprocess.run(f"chmod -R 750 {config_dir}", shell=True)
        # Archivos .json en config deben ser 640 (rw-r-----)
        subprocess.run(f"find {config_dir} -type f -name '*.json' -exec chmod 640 {{}} \\;", shell=True)
    
    # Core: solo lectura y ejecución para jsbach (r-x)
    core_dir = os.path.join(target_path, "app", "core")
    if os.path.exists(core_dir):
        info(f"  Core: 550 (r-xr-x---) - solo lectura/ejecución")
        subprocess.run(f"chmod 550 {core_dir}", shell=True)
        # Archivos .py en core: 440 (r--r-----)
        subprocess.run(f"find {core_dir} -type f -name '*.py' -exec chmod 440 {{}} \\;", shell=True)
    
    # App (otros directorios): lectura/ejecución
    app_dir = os.path.join(target_path, "app")
    if os.path.exists(app_dir):
        info(f"  App: 550 (r-xr-x---) para directorios")
        for subdir in ["cli", "controllers", "utils"]:
            subdir_path = os.path.join(app_dir, subdir)
            if os.path.exists(subdir_path):
                subprocess.run(f"chmod 550 {subdir_path}", shell=True)
                subprocess.run(f"find {subdir_path} -type f -name '*.py' -exec chmod 440 {{}} \\;", shell=True)
    
    # Logs: jsbach puede escribir
    logs_dir = os.path.join(target_path, "logs")
    if os.path.exists(logs_dir):
        info(f"  Logs: 750 (rwxr-x---) - jsbach puede escribir")
        subprocess.run(f"chmod -R 750 {logs_dir}", shell=True)
    
    # Web: solo lectura
    web_dir = os.path.join(target_path, "web")
    if os.path.exists(web_dir):
        info(f"  Web: 550 (r-xr-x---) - solo lectura")
        subprocess.run(f"chmod -R 550 {web_dir}", shell=True)
        subprocess.run(f"find {web_dir} -type f -exec chmod 440 {{}} \\;", shell=True)
    
    # Main.py: solo lectura/ejecución
    main_py = os.path.join(target_path, "main.py")
    if os.path.exists(main_py):
        info(f"  main.py: 550 (r-xr-x---)")
        subprocess.run(f"chmod 550 {main_py}", shell=True)
    
    success("Permisos configurados correctamente")

def create_systemd_service(target_path, venv_path, port):
    info("Creando servicio systemd")
    service_content = f"""[Unit]
Description=JSBach V4.0 Web Service
After=network.target

[Service]
Type=simple
User=jsbach
Group=jsbach
WorkingDirectory={target_path}
Environment="PATH={venv_path}/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ExecStart={venv_path}/bin/python3 -m uvicorn main:app --host 0.0.0.0 --port {port}
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"""
    service_path = "/etc/systemd/system/jsbach.service"
    with open(service_path, "w") as f:
        f.write(service_content)

    # Asegurar permisos correctos para el directorio del proyecto
    set_directory_permissions(target_path)

    cmds = ["systemctl daemon-reload",
            "systemctl enable jsbach",
            "systemctl restart jsbach"]
    for c in cmds:
        result = subprocess.run(c, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        if result.returncode != 0:
            error(f"Fallo al ejecutar: {c}\n{result.stderr.strip()}")
    success("Servicio systemd creado y en ejecución")


###############
#   Función para modificar sudoers
###############
def add_sudoers_entry(user, commands):
    sudoers_path = "/etc/sudoers.d/99_jsbach"

    # Asegurarnos de que el archivo sudoers existe y es seguro
    if not os.path.exists(sudoers_path):
        info(f"Creando archivo de sudoers para {user}")

    sudoers_entry = f"{user} ALL=(ALL) NOPASSWD: " + ", ".join(commands) + "\n"

    # Añadir al archivo sudoers
    with open(sudoers_path, "a") as f:
        f.write(sudoers_entry)

    success(f"Se ha añadido la entrada de sudoers para el usuario {user}")

###############
#   Crear archivo de autenticación
###############
def create_auth_file(target_path, username, password):
    """Crear archivo cli_users.json con el usuario inicial."""
    config_dir = os.path.join(target_path, "config")
    auth_file = os.path.join(config_dir, "cli_users.json")
    
    # Hash de la contraseña
    password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
    
    # Estructura del usuario
    user_data = {
        "users": [
            {
                "username": username,
                "password_hash": f"sha256:{password_hash}",
                "role": "admin",
                "created_at": datetime.now().isoformat(),
                "enabled": True
            }
        ]
    }
    
    info(f"Creando archivo de autenticación en {auth_file}")
    try:
        with open(auth_file, 'w') as f:
            json.dump(user_data, f, indent=4)
        
        # Cambiar permisos y propietario
        subprocess.run(f"chown jsbach:jsbach {auth_file}", shell=True)
        subprocess.run(f"chmod 600 {auth_file}", shell=True)  # Solo lectura/escritura para el propietario
        
        success("Archivo de autenticación creado correctamente")
    except Exception as e:
        error(f"No se pudo crear el archivo de autenticación: {e}")

###############
#   MAIN
###############
if __name__ == "__main__":
    if platform.system() == "Windows":
        message = r"""
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣤⣤⣤⣤⠤⠤⠤⠤⢤⣤⣤⣤⣤⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⠛⢉⡁⠀⠀⠀⢀⡀⠀⠀⠀⠐⠒⠁⠀⢴⡌⠻⣯⡙⠳⣶⡄⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⡾⠷⢋⠉⠀⠀⢀⣀⠁⠀⠀⠐⠀⠈⠹⣆⡀⢬⠻⣦⢹⣿⣧⡈⣿⡀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⠟⣀⡴⠛⠂⠀⠀⠃⠀⠀⠀⠀⠀⠀⠀⣄⠘⢷⡘⠀⠀⠘⣿⣟⠃⢸⣇⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⠏⠈⡁⠀⠀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠃⠀⠻⠶⣄⡆⢨⣿⠳⣌⣿⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⠁⠈⠁⠀⠀⠋⠁⠀⢠⠀⠀⠀⠀⠀⠀⠀⡄⠀⠀⠀⣤⠀⣛⠃⢀⣿⠀⣮⣿⡇⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣤⣇⣴⣼⣒⣶⣶⣶⣶⣴⣖⣀⣀⠀⠀⠀⠃⢠⡇⠀⠸⠃⠻⡄⠘⣷⢀⣸⣿⣇⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣾⣧⣤⣤⣤⣠⠏⢠⠙⠘⣿⡿⣿⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠟⠻⣿⡆⠘⢻⠿⣴⣦⣿⣟⣿⡆⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠟⠁⠀⠀⢀⣿⣇⢀⠀⣿⣱⣿⣷⠿⣿⡇⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⣿⣿⣿⠟⠉⣉⠉⠙⣿⣿⣿⠛⠉⠀⠀⠀⠀⠀⠀⠸⢧⣾⠀⣹⣿⣀⣿⡖⢺⣷⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⠏⠎⠉⠀⣀⠘⢁⡶⢰⣿⠀⠀⠷⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⢯⣝⣭⡍⢹⣇⢸⣿⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢠⡟⢀⣴⠂⠀⢀⣴⡿⠁⣼⠃⠀⠀⢀⡠⠀⠀⢀⡀⢀⣼⡿⠀⠉⠀⠉⠀⠉⢸⣿⣿⣻⣇⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⣿⣵⠟⠁⢀⣼⣿⣿⠃⢰⠇⠀⢀⡰⠋⣠⡚⠂⠀⠀⠀⠛⠁⠀⠀⠀⠀⠀⢀⡈⢻⣟⢻⣿⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⣸⠟⠁⢀⣴⡯⠉⣸⡟⠀⢰⡏⠀⠈⠁⠀⠀⠀⠀⠤⠴⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⡄⢻⣧⣿⡇⠀⠀
⠀⠀⠀⠀⠀⢀⣴⠟⢀⡴⠛⢓⣤⠜⣿⠁⠀⠉⠃⡄⠀⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⢰⣿⣧⣿⡙⢿⣷⠀⠀
⠀⠀⠀⢀⡴⠟⢁⡴⠛⠉⠉⠁⠀⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⢀⠀⠀⠸⠛⢿⣿⠝⠃⠀⢿⡀⠀
⠀⢀⣼⡋⠀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠃⠀⠀⠀⠀⠀⠹⠀⠀⠀⠀⠸⣿⡄⠀⠸⠿⣧⠀
⢠⣾⣿⣿⣷⣤⣤⣤⣄⣠⡄⠀⠀⠀⠀⠤⢀⣀⣼⠿⢆⣰⣶⠀⠀⠀⠀⠀⠀⠀⠀⣠⡶⠀⠀⠀⠀⠀⢸⣷⣆⠈⢧⣿⠀
⠀⠙⠻⠿⣿⣿⣿⣿⣿⣿⣿⣷⣶⣶⣶⣶⣶⣿⣷⣾⣽⣧⣇⠀⠀⢀⡀⠀⠀⠀⣼⠋⠿⠀⠀⠀⠀⠀⠀⠉⢻⣿⣀⣿⡄
⠀⠀⠀⠀⢀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⠋⠉⠀⠀⠀⠀⠀⠀⠐⣾⡆⢠⣶⣿⣿⣿⣶⣶⣾⣿⣿⣿⣿⡇
⠀⠀⠀⠀⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠿⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠼⠟⢁⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇
⠀⠀⠀⣰⡿⠟⠛⠛⠛⠛⠋⠉⠋⠈⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⡿⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇
⠀⠀⠀⣿⣿⣿⣶⣶⣶⣶⣶⣦⣤⣤⣤⣤⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⠀⠀⠀⠀⠈⠃⠲⢢⣿⣿⣿⣿⣿⣿⣿⣿⡇
⠀⠀⠀⠹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣗⣶⠁⢀⣄⠀⠀⠂⠀⠀⠀⠀⠀⠀⠀⠀⠾⣿⣿⣿⣿⣿⣿⣿⣿⡇
⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⣿⣿⣶⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢨⣽⣿⣿⣿⣿⣿⣿⡇
⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠿⠟⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢈⣿⣿⣿⣿⣿⣿⡇
⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⣛⣿⣿⣿⣿⣿⣿⡇
⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⡟⠁⠀⠀⠀⠀⠀⢀⡀⠀⠀⠀⠀⠀⠔⠃⠀⠀⠀⣀⣠⣤⣿⣿⣿⣿⣿⣿⣿⣿⡇
⠀⠀⠀⠀⠀⠻⣿⣿⣿⣿⣿⣿⣤⣤⣤⡀⠀⢀⣴⠞⠋⢀⣠⡀⠀⠀⠀⢰⣿⣶⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀
⠀⠀⠀⠀⠀⠀⠙⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣾⣿⣷⣾⣶⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠁⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⠻⠿⠿⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠋⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⠀⠀⠀⠀⠀⠈⠉⠉⠉⠙⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠉⠁⣀⣀⠀⠀⠀⠀
"""
        print(message)
        sys.exit(1)

    ensure_root()
    info("Instalador JSBach V4.0")

    # Preguntar ruta de instalación
    target_path = ask("Ruta de instalación del proyecto", "/opt/JSBach_V4.0")
    target_path = target_path.rstrip("/")

    if target_path == "/":
        warn("Has elegido '/' como ruta de instalación. Esto puede ser peligroso.")
        if ask_yes_no("Continuar?", "n") == "n":
            sys.exit(0)

    install_dependencies()
    create_user("jsbach")
    prepare_directory(target_path)
    create_logs_directory(target_path)
    create_config_directory(target_path)
    venv_path = create_venv(target_path)

    # Elegir puerto
    while True:
        port = ask("Puerto donde se ejecutará la web", "8100")
        if port not in ("80","8080","8000"):
            break
        warn("El puerto 80, 8080 y 8000 están ocupados. Escoge otro.")

    # Configurar credenciales de autenticación
    print()
    info("Configuración de credenciales de acceso")
    username = ask("Usuario para el sistema", "admin")
    password = ask("Contraseña", "")
    
    # Advertencia si la contraseña está vacía
    if not password:
        warn("⚠️  La contraseña está vacía. Esto es inseguro.")
        if ask_yes_no("¿Continuar sin contraseña?", "n") == "n":
            # Forzar que introduzca una contraseña
            while not password:
                password = ask("Contraseña (obligatoria)", "")
                if not password:
                    warn("Debe introducir una contraseña")
    
    print()

    create_systemd_service(target_path, venv_path, port)
    create_cli_systemd_service(target_path, venv_path)

    # Definir los comandos permitidos en sudoers
    allowed_commands = [
        "/usr/sbin/ip *",
        "/usr/sbin/dhcpcd *",
        "/usr/bin/resolvectl *",
        "/usr/sbin/iptables *",
        "/usr/sbin/bridge *",
        "/usr/sbin/ebtables *",
        "/usr/sbin/sysctl -w net.ipv4.ip_forward=1",
        "/usr/sbin/sysctl -w net.ipv4.ip_forward=0",
        "/usr/sbin/sysctl -n net.ipv4.ip_forward"
    ]

    # Añadir sudoers
    add_sudoers_entry("jsbach", allowed_commands)
    
    # Crear archivo de autenticación
    create_auth_file(target_path, username, password)

    success(f"Instalación completada. Accede a la web en http://localhost:{port}/")
    success(f"Instalación completada. Accede a la web en http://<tu-ip>:{port}/\n")

    # Mostrar credenciales
    if password:
        info(f"Puede iniciar sesión con usuario '{username}' y contraseña '{password}'")
    else:
        info(f"Puede iniciar sesión con usuario '{username}' y contraseña vacía")
    
    print()
    info("Para administrar el servicio JSBach V4.0, usa los siguientes comandos:")
    print("  systemctl status jsbach      # Ver estado del servicio")
    print("  systemctl restart jsbach     # Reiniciar el servicio")
    print("  systemctl stop jsbach        # Detener el servicio")
    print("  systemctl start jsbach       # Iniciar el servicio")
    print("  journalctl -u jsbach -f      # Ver logs en tiempo real")