#!/usr/bin/env python3

import os
import shutil
import subprocess
import sys
import platform

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

###############
#   QOL       #
###############
def ask_yes_no(question, default="n"):
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
#   Detener y eliminar servicio systemd
###############
def remove_systemd_service():
    service_path = "/etc/systemd/system/jsbach.service"
    
    if not os.path.exists(service_path):
        warn("El servicio systemd no existe")
        return
    
    info("Deteniendo y eliminando servicio systemd")
    
    # Detener el servicio
    cmd("systemctl stop jsbach")
    result = subprocess.run("/usr/bin/systemctl stop jsbach", shell=True, 
                          stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        warn(f"No se pudo detener el servicio: {result.stderr.strip()}")
    
    # Deshabilitar el servicio
    cmd("systemctl disable jsbach")
    result = subprocess.run("/usr/bin/systemctl disable jsbach", shell=True,
                          stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        warn(f"No se pudo deshabilitar el servicio: {result.stderr.strip()}")
    
    # Eliminar el archivo del servicio
    try:
        os.remove(service_path)
        success(f"Servicio systemd eliminado: {service_path}")
    except Exception as e:
        warn(f"No se pudo eliminar {service_path}: {e}")
    
    # Recargar systemd
    cmd("systemctl daemon-reload")
    subprocess.run("/usr/bin/systemctl daemon-reload", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run("/usr/bin/systemctl reset-failed", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

###############
#   Eliminar sudoers
###############
def remove_sudoers():
    sudoers_path = "/etc/sudoers.d/99_jsbach"
    
    if not os.path.exists(sudoers_path):
        warn("El archivo sudoers no existe")
        return
    
    info(f"Eliminando archivo sudoers: {sudoers_path}")
    try:
        os.remove(sudoers_path)
        success("Archivo sudoers eliminado")
    except Exception as e:
        error(f"No se pudo eliminar el archivo sudoers: {e}")

###############
#   Eliminar directorio del proyecto
###############
def remove_project_directory(target_path):
    if not os.path.exists(target_path):
        warn(f"El directorio {target_path} no existe")
        return
    
    info(f"Eliminando directorio del proyecto: {target_path}")
    
    # Confirmar eliminación
    warn(f"Se eliminará completamente el directorio: {target_path}")
    warn("Esto incluye: código, configuraciones, logs, y el entorno virtual")
    
    if ask_yes_no("¿Estás seguro de que deseas continuar?", "n") == "n":
        info("Operación cancelada por el usuario")
        return False
    
    try:
        shutil.rmtree(target_path)
        success(f"Directorio eliminado: {target_path}")
        return True
    except Exception as e:
        error(f"No se pudo eliminar el directorio: {e}")

###############
#   Eliminar usuario
###############
def remove_user(username="jsbach"):
    # Verificar si el usuario existe
    try:
        subprocess.run(f"/usr/bin/id -u {username}", shell=True, check=True, 
                      stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError:
        warn(f"El usuario {username} no existe")
        return
    
    info(f"El usuario '{username}' existe en el sistema")
    
    if ask_yes_no(f"¿Deseas eliminar el usuario '{username}' y su directorio home?", "n") == "s":
        cmd(f"userdel -r {username}")
        result = subprocess.run(f"/usr/sbin/userdel -r {username}", shell=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode == 0:
            success(f"Usuario {username} eliminado correctamente")
        else:
            warn(f"No se pudo eliminar el usuario completamente: {result.stderr.strip()}")
    else:
        info(f"Usuario {username} conservado")

###############
#   Limpiar reglas de firewall/iptables
###############
def clean_iptables_rules():
    info("Verificando reglas de iptables creadas por JSBach")
    
    if ask_yes_no("¿Deseas limpiar todas las reglas de iptables de JSBach?", "n") == "s":
        warn("ADVERTENCIA: Esto eliminará todas las cadenas y reglas personalizadas de JSBach")
        warn("Incluyendo: NAT, DMZ, VLANs de firewall, etc.")
        
        if ask_yes_no("¿Confirmas la eliminación de reglas de iptables?", "n") == "s":
            cmd("Limpiando reglas de iptables...")
            
            # Limpiar NAT
            subprocess.run("/usr/sbin/iptables -t nat -F", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run("/usr/sbin/iptables -t nat -X", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Limpiar filter
            subprocess.run("/usr/sbin/iptables -F", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run("/usr/sbin/iptables -X", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Desactivar IP forwarding
            subprocess.run("/usr/sbin/sysctl -w net.ipv4.ip_forward=0", shell=True, 
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            success("Reglas de iptables limpiadas")
    else:
        info("Reglas de iptables conservadas")

###############
#   Limpiar interfaces de red
###############
def clean_network_interfaces():
    info("Verificando interfaces de red creadas por JSBach")
    
    if ask_yes_no("¿Deseas eliminar el bridge br0 y las interfaces VLAN?", "n") == "s":
        warn("Esto eliminará: br0, interfaces VLAN (vlan.*), y configuraciones de tagging")
        
        if ask_yes_no("¿Confirmas la eliminación de interfaces de red?", "n") == "s":
            cmd("Eliminando interfaces de red...")
            
            # Verificar si br0 existe
            if os.path.exists("/sys/class/net/br0"):
                subprocess.run("/usr/sbin/ip link set br0 down", shell=True, 
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run("/usr/sbin/ip link delete br0", shell=True, 
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                success("Bridge br0 eliminado")
            
            # Eliminar interfaces VLAN
            result = subprocess.run("/usr/sbin/ip -o link show | grep vlan | awk '{print $2}' | sed 's/:$//'", 
                                  shell=True, capture_output=True, text=True)
            if result.stdout.strip():
                vlan_interfaces = result.stdout.strip().split('\n')
                for iface in vlan_interfaces:
                    subprocess.run(f"/usr/sbin/ip link delete {iface}", shell=True,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                success(f"Interfaces VLAN eliminadas: {', '.join(vlan_interfaces)}")
            
            success("Interfaces de red limpiadas")
    else:
        info("Interfaces de red conservadas")

###############
#   MAIN
###############
if __name__ == "__main__":
    if platform.system() == "Windows":
        print("Este script solo funciona en sistemas Linux")
        sys.exit(1)

    ensure_root()
    
    print(f"{RED}")
    print("=" * 60)
    print("   DESINSTALADOR JSBach V4.0")
    print("=" * 60)
    print(f"{RESET}")
    
    warn("Este script eliminará JSBach V4.0 del sistema")
    warn("Se eliminarán: servicio, archivos, configuraciones y logs")
    
    if ask_yes_no("¿Deseas continuar con la desinstalación?", "n") == "n":
        info("Desinstalación cancelada")
        sys.exit(0)
    
    print()
    
    # 1. Detener y eliminar servicio
    remove_systemd_service()
    
    # 2. Limpiar reglas de firewall
    clean_iptables_rules()
    
    # 3. Limpiar interfaces de red
    clean_network_interfaces()
    
    # 4. Eliminar sudoers
    remove_sudoers()
    
    # 5. Eliminar directorio del proyecto
    target_path = input(f"{BLUE}[INFO]{RESET} Ruta del proyecto instalado [/opt/JSBach_V4.0]: ").strip()
    if not target_path:
        target_path = "/opt/JSBach_V4.0"
    
    removed = remove_project_directory(target_path)
    
    # 6. Eliminar usuario (opcional)
    if removed:
        remove_user("jsbach")
    
    print()
    print(f"{GREEN}{'=' * 60}{RESET}")
    success("Desinstalación completada")
    print(f"{GREEN}{'=' * 60}{RESET}")
    
    info("Notas:")
    print("  • Las dependencias del sistema (python3, pip, venv) NO se han eliminado")
    print("    ya que pueden ser usadas por otros programas")
    print("  • Si conservaste interfaces de red o reglas de iptables,")
    print("    puedes eliminarlas manualmente cuando lo desees")
    print()
