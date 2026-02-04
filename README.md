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

- **WAN**: Configuración de interfaz de red externa (DHCP/Estática)
- **VLANs**: Creación y gestión de redes virtuales
- **Firewall**: Gestión de reglas de seguridad y whitelist por VLAN
- **NAT**: Network Address Translation para enmascaramiento de red
- **DMZ**: Zona desmilitarizada para servicios expuestos
- **Tagging**: Etiquetado de tráfico VLAN en interfaces físicas
- **Ebtables**: Aislamiento de VLANs a nivel de capa 2 (Ethernet)

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

### Ayuda desde el CLI

Para información detallada sobre comandos y uso del sistema:

- **Interfaz CLI**: Conecta al CLI y escribe `help` para ver todos los comandos disponibles
- **Ayuda por módulo**: Escribe `help <módulo>` (ej: `help wan`, `help firewall`, `help ebtables`)
- **Documentación detallada**: Cada módulo tiene documentación completa en `app/cli/help/`

### Módulos documentados

| Módulo | Archivo | Descripción |
|--------|---------|-------------|
| WAN | [wan.md](app/cli/help/wan.md) | Configuración de interfaz WAN (DHCP/Estática) |
| VLANs | [vlans.md](app/cli/help/vlans.md) | Creación y gestión de redes virtuales |
| Firewall | [firewall.md](app/cli/help/firewall.md) | Reglas de seguridad y whitelists |
| NAT | [nat.md](app/cli/help/nat.md) | Network Address Translation |
| DMZ | [dmz.md](app/cli/help/dmz.md) | Zona desmilitarizada |
| Tagging | [tagging.md](app/cli/help/tagging.md) | Etiquetado VLAN en interfaces |
| Ebtables | [ebtables.md](app/cli/help/ebtables.md) | Aislamiento L2 de VLANs |

### Pruebas

Ejecuta el suite de pruebas para validar la instalación:

```bash
cd /opt/JSBach_V4.0
python3 test_web_endpoints.py
```

Este script prueba:
- ✅ Autenticación y acceso web
- ✅ Endpoints de API `/admin`
- ✅ Archivos estáticos (CSS/JS modulares)
- ✅ Protección de rutas sin autenticación
- ✅ Configuraciones de todos los módulos

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
│   │   └── help/     # Documentación de módulos (Markdown)
│   ├── controllers/  # Controladores FastAPI
│   │   ├── main_controller.py   # Rutas principales y middleware
│   │   └── admin_router.py      # API de administración
│   ├── core/         # Módulos de red (wan, nat, firewall, etc.)
│   └── utils/        # Utilidades compartidas (helpers, auth, logging)
├── config/           # Configuraciones JSON por módulo
├── install/          # Scripts de instalación/desinstalación
├── logs/             # Logs del sistema por módulo
├── web/              # Interfaz web
│   └── [module]/     # Páginas HTML por módulo
└── main.py           # Punto de entrada de la aplicación
```

### Tecnologías utilizadas

- **Backend**: Python 3.8+, FastAPI, Uvicorn
- **Frontend**: HTML5, CSS3 modular, JavaScript vanilla
- **CLI**: asyncio, socket TCP (puerto 2200)
- **Networking**: iptables, iproute2, ebtables
- **Sistema**: systemd, sudoers

### Arquitectura

- **Helpers centralizados**: Módulos compartidos en `app/utils/` para config, validación y logging
- **API RESTful**: Endpoints en `/admin/` para gestión de módulos
- **Frontend modular**: CSS y JavaScript embebido en cada página HTML
- **Autenticación**: Sistema de sesiones con middleware de protección
- **Logs estructurados**: Registro de acciones por módulo en `logs/`

---

## ⚙️ Características Técnicas

### Backend Modularizado

- **Helpers centralizados**: Todas las funciones comunes (carga de configs, validación, logging) en `app/utils/`
- **Reducción de código duplicado**: ~1,200 líneas de código reutilizable
- **Gestión de errores consistente**: Manejo uniforme en todos los módulos
- **Logging estructurado**: Registro detallado de todas las acciones

### Frontend Modular

- **CSS separado**: 5 archivos CSS modulares (global, buttons, cards, forms, header)
- **JavaScript separado**: 2 archivos JS (app.js, utils.js)
- **Sin dependencias externas**: HTML/CSS/JS vanilla, sin frameworks
- **Responsive**: Diseño adaptable a diferentes resoluciones

### API RESTful

- **Endpoints documentados**: API completa en `/admin/`
- **Autenticación por sesión**: Middleware de protección
- **Respuestas JSON**: Formato estándar para todas las respuestas
- **Gestión de errores**: Códigos HTTP apropiados (200, 400, 404, etc.)

### Seguridad

- **Autenticación obligatoria**: Todas las rutas protegidas por login
- **Hashing de contraseñas**: SHA256 para almacenamiento seguro
- **Validación de inputs**: Sanitización de parámetros en todos los módulos
- **Logs de auditoría**: Registro de todas las acciones administrativas

---

**JSBach V4.0** - Sistema profesional de gestión de router 🚀