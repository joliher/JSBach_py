# JSBach V4.0

**Sistema de gestión y administración de router con interfaz web y CLI**

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-green)](https://fastapi.tiangolo.com/)

---

## 📋 Descripción

JSBach V4.0 es un sistema completo de gestión de router que permite configurar y administrar servicios de red a través de dos interfaces:

- **🌐 Interfaz Web** (puerto 8100): Panel de administración con interfaz gráfica
- **⌨️ Interfaz CLI** (puerto 2200): Terminal interactivo vía TCP

### Módulos disponibles

- **WAN**: Configuración de interfaz de red externa
- **NAT**: Network Address Translation
- **Firewall**: Gestión de reglas de seguridad y whitelist por VLAN
- **DMZ**: Zona desmilitarizada para servicios expuestos
- **VLANs**: Creación y gestión de redes virtuales
- **Tagging**: Etiquetado de tráfico en interfaces

---

## 🚀 Instalación

### Requisitos

- Sistema operativo: **Linux** (Debian/Ubuntu recomendado)
- Python 3.8+
- Permisos de **root** para la instalación

### Proceso de instalación

1. **Clonar el repositorio**:
```bash
git clone https://github.com/joliher/JSBach
cd JSBach_V4.0
```

2. **Ejecutar el instalador como root**:
```bash
sudo python3 install/install.py
```

3. **Configurar durante la instalación**:
   - Ruta de instalación (por defecto: `/opt/JSBach_V4.0`)
   - Puerto web (por defecto: `8100`)
   - Usuario y contraseña de administración

### ¿Qué hace el instalador?

- ✅ Instala dependencias del sistema (python3, python3-pip, python3-venv)
- ✅ Crea el usuario del sistema **jsbach**
- ✅ Copia los archivos del proyecto a `/opt/JSBach_V4.0`
- ✅ Crea un entorno virtual Python
- ✅ Instala paquetes Python (FastAPI, uvicorn)
- ✅ Configura permisos de archivos
- ✅ Crea un **servicio systemd** (`jsbach.service`)
- ✅ Configura **sudoers** para comandos de red necesarios
- ✅ Crea archivo de autenticación en `config/cli_users.json`

### Servicio systemd

JSBach se ejecuta como un servicio systemd:

```bash
# Ver estado del servicio
sudo systemctl status jsbach

# Iniciar servicio
sudo systemctl start jsbach

# Detener servicio
sudo systemctl stop jsbach

# Reiniciar servicio
sudo systemctl restart jsbach

# Ver logs en tiempo real
sudo journalctl -u jsbach -f
```

El servicio se ejecuta bajo el usuario **jsbach** y se inicia automáticamente al arrancar el sistema.

---

## 🌐 Acceso al sistema

### Interfaz Web

Accede desde tu navegador:

```
http://localhost:8100
```

Utilizar las credenciales configuradas durante la instalación

### Interfaz CLI

Conéctate vía TCP usando netcat o telnet:

```bash
# Usando netcat
nc localhost 2200

# Usando telnet
telnet localhost 2200
```

Credenciales: las mismas que la interfaz web.

---

## 📚 Documentación

Para información detallada sobre comandos y uso del sistema:

- **Interfaz CLI**: Conecta al CLI y escribe `help` para ver todos los comandos disponibles
- **Ayuda por módulo**: Escribe `help <módulo>` (ej: `help wan`, `help firewall`) para ayuda específica
- **Documentación técnica**: [app/cli/help/CLI_COMMANDS.md](app/cli/help/CLI_COMMANDS.md)

---

## 🗑️ Desinstalación

Para desinstalar completamente JSBach V4.0:

```bash
sudo python3 install/uninstall.py
```

El desinstalador te preguntará qué elementos deseas eliminar:

- ✅ Servicio systemd
- ✅ Reglas de iptables (opcional)
- ✅ Interfaces de red creadas (opcional)
- ✅ Configuración sudoers
- ✅ Directorio del proyecto
- ✅ Usuario jsbach (opcional)

**Nota**: Las dependencias del sistema (python3, pip) NO se eliminan ya que pueden ser usadas por otros programas.

---

## 🛠️ Desarrollo

### Estructura del proyecto

```
JSBach_V4.0/
├── app/
│   ├── cli/          # Interfaz CLI (servidor TCP)
│   │   └── help/     # Archivos de ayuda CLI
│   ├── controllers/  # Controladores FastAPI
│   ├── core/         # Módulos principales (NAT, Firewall, etc.)
│   └── utils/        # Utilidades compartidas
├── config/           # Archivos de configuración JSON
├── install/          # Scripts de instalación/desinstalación
├── logs/             # Logs del sistema
├── web/              # Interfaz web (HTML/CSS/JS)
└── main.py           # Punto de entrada de la aplicación
```

### Tecnologías utilizadas

- **Backend**: Python 3, FastAPI, uvicorn
- **Frontend**: HTML5, CSS3, JavaScript vanilla
- **CLI**: asyncio, socket TCP
- **Sistema**: systemd, iptables, iproute2

---

## 🧪 Pruebas

Ejecuta el suite de pruebas automatizadas:

```bash
cd /opt/JSBach_V4.0
python3 install/test_services.py
```

Este script prueba:
- ✅ Configuración de VLANs, Firewall, DMZ, Tagging
- ✅ Activación/desactivación de servicios
- ✅ Comandos CLI y endpoints Web
- ✅ 33 pruebas automatizadas

---

**JSBach V4.0** - Sistema profesional de gestión de router 🚀