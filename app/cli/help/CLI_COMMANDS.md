# Comandos CLI - JSBach V4.0

## Descripción

El CLI de JSBach V4.0 proporciona una interfaz de línea de comandos a través de TCP en el puerto 2200, permitiendo gestionar todos los módulos del sistema de forma remota.

## Características

- **Autenticación segura**: Sistema de usuarios con SHA256
- **Conexión TCP**: Puerto 2200, compatible con netcat, telnet
- **Comandos interactivos**: Shell interactivo con prompt personalizado
- **Sistema de ayuda**: Comando `help` con documentación integrada
- **Ejecución remota**: Gestiona el router desde cualquier máquina en la red

---

## 🔌 Conexión

### Usando netcat (nc)
```bash
nc <ip_del_router> 2200
```

### Usando telnet
```bash
telnet <ip_del_router> 2200
```

### Ejemplo local
```bash
nc localhost 2200
```

## 🔐 Autenticación

Al conectar, se solicitará:
```
Username: admin
Password: password123
```

Las credenciales se configuran durante la instalación y se almacenan en `/opt/JSBach_V4.0/config/cli_users.json`.

---

## 📋 Comandos Disponibles

### Formato general
```
<módulo> <acción> [--params '{json}']
```

### Módulos disponibles
- **wan** - Gestión de interfaz WAN
- **nat** - Network Address Translation
- **firewall** - Firewall y reglas de seguridad
- **dmz** - Zona desmilitarizada
- **vlans** - Redes VLAN
- **tagging** - Etiquetado de tráfico

### Acciones comunes
- `start` - Iniciar el módulo
- `stop` - Detener el módulo
- `restart` - Reiniciar el módulo
- `status` - Ver estado del módulo
- `config` - Configurar el módulo

### Comandos especiales
- `help` - Mostrar ayuda general
- `help <módulo>` - Ayuda específica de un módulo
- `exit` o `quit` - Cerrar sesión

---

## 🌐 Módulo WAN

Gestiona la configuración de la interfaz de red externa.

### Comandos

#### Ver estado
```bash
wan status
```

#### Configurar con DHCP
```bash
wan config {"mode": "dhcp", "interface": "eth0"}
```

#### Configurar con IP estática
```bash
wan config {"mode": "static", "interface": "eth0", "ip": "192.168.1.100", "netmask": "255.255.255.0", "gateway": "192.168.1.1", "dns": ["8.8.8.8", "8.8.4.4"]}
```

#### Iniciar WAN
```bash
wan start
```

#### Detener WAN
```bash
wan stop
```

#### Reiniciar WAN
```bash
wan restart
```

---

## 🔄 Módulo NAT

Network Address Translation para compartir conexión a Internet.

### Comandos

#### Configurar NAT
```bash
nat config {"wan_interface": "eth0", "lan_interfaces": ["eth1", "eth2"]}
```

#### Ver estado
```bash
nat status
```

#### Iniciar NAT
```bash
nat start
```

#### Detener NAT
```bash
nat stop
```

#### Reiniciar NAT
```bash
nat restart
```

---

## 🔒 Módulo Firewall

Gestión de reglas de seguridad por VLAN.

### Comandos básicos

#### Ver estado
```bash
firewall status
```

#### Iniciar firewall
```bash
firewall start
```

#### Detener firewall
```bash
firewall stop
```

#### Reiniciar firewall
```bash
firewall restart
```

### Gestión de whitelist

#### Habilitar whitelist en una VLAN
```bash
firewall enable_whitelist {"vlan_id": 10, "whitelist": ["8.8.8.8", "1.1.1.1", "208.67.222.222"]}
```

#### Deshabilitar whitelist
```bash
firewall disable_whitelist {"vlan_id": 10}
```

### Gestión de reglas

#### Añadir regla a whitelist
```bash
firewall add_rule {"vlan_id": 10, "rule": "4.4.4.4"}
```

#### Eliminar regla de whitelist
```bash
firewall remove_rule {"vlan_id": 10, "rule": "4.4.4.4"}
```

### Restricción de VLANs (botón RESTRINGIR)

Bloquea el acceso al router (INPUT) desde una VLAN.

- **VLAN 1 y 2**: bloqueo total hacia el router.
- **Otras VLANs**: solo se permiten DHCP (67/68 UDP), DNS (53 TCP/UDP) e ICMP; todo lo demás se bloquea.
- Compatible con aislamiento y whitelist (se evalúa en `INPUT_RESTRICTIONS`).

#### Restringir una VLAN
```bash
firewall restrict {"vlan_id": 20}
```

#### Quitar restricción
```bash
firewall unrestrict {"vlan_id": 20}
```


### Aislamiento de VLANs

El aislamiento bloquea completamente el acceso a Internet desde una VLAN.

#### Aislar VLAN (sin acceso a internet)
```bash
firewall aislar {"vlan_id": 20}
```

**Funcionamiento:**
- Inserta DROP en FORWARD_PROTECTION posición 1
- Prioridad MÁXIMA sobre whitelist y otras reglas
- Bloquea TODO el tráfico hacia Internet
- La VLAN mantiene comunicación interna

#### Desaislar VLAN (restaurar acceso)
```bash
firewall desaislar {"vlan_id": 20}
```

**Funcionamiento:**
- Elimina la regla DROP de FORWARD_PROTECTION
- Restaura acceso según configuración (whitelist si estaba activa)

---

## 🛡️ Módulo DMZ

Zona desmilitarizada para servicios expuestos a Internet.

### Comandos básicos

#### Ver estado
```bash
dmz status
```

#### Iniciar DMZ
```bash
dmz start
```

#### Detener DMZ
```bash
dmz stop
```

#### Reiniciar DMZ
```bash
dmz restart
```

### Gestión de destinos

#### Añadir destino DMZ
```bash
dmz config {"ip": "192.168.3.10", "port": 80, "protocol": "tcp"}
```

#### Eliminar destino DMZ
```bash
dmz eliminar {"ip": "192.168.3.10", "port": 80, "protocol": "tcp"}
```

### Aislamiento de hosts DMZ

El aislamiento de un host DMZ lo bloquea COMPLETAMENTE (bidireccional).

#### Aislar host DMZ
```bash
dmz aislar {"ip": "10.0.5.50"}
```

**Funcionamiento:**
- DROP en FORWARD_PROTECTION (-d IP): Bloquea tráfico HACIA el host
- DROP en INPUT (-s IP): Bloquea tráfico DESDE el host hacia router
- Aislamiento COMPLETO: el host no puede comunicarse
- Útil para contener hosts comprometidos inmediatamente
- Prioridad MÁXIMA sobre DMZ y whitelist

**Nota:** Solo requiere la IP del host, no puerto ni protocolo.

#### Desaislar host DMZ
```bash
dmz desaislar {"ip": "10.0.5.50"}
```

**Funcionamiento:**
- Elimina DROP de FORWARD_PROTECTION e INPUT
- Restaura funcionalidad normal del host DMZ

---

## 🔀 Módulo VLANs

Creación y gestión de redes virtuales.

### Comandos básicos

#### Ver estado
```bash
vlans status
```

#### Iniciar VLANs
```bash
vlans start
```

#### Detener VLANs
```bash
vlans stop
```

#### Reiniciar VLANs
```bash
vlans restart
```

### Gestión de VLANs

#### Añadir VLAN
```bash
vlans config {"action": "add", "id": 10, "name": "Oficina", "ip_interface": "192.168.10.1/24", "ip_network": "192.168.10.0/24"}
```

#### Eliminar VLAN
```bash
vlans config {"action": "remove", "id": 10}
```

#### Mostrar configuración
```bash
vlans config {"action": "show"}
```

---

## 🏷️ Módulo Tagging

Etiquetado de tráfico VLAN en interfaces físicas.

### Comandos básicos

#### Ver estado
```bash
tagging status
```

#### Iniciar tagging
```bash
tagging start
```

#### Detener tagging
```bash
tagging stop
```

#### Reiniciar tagging
```bash
tagging restart
```

### Gestión de interfaces

#### Añadir interfaz con VLAN UNTAG
```bash
tagging config {"action": "add", "name": "eth1", "vlan_untag": "10", "vlan_tag": ""}
```

#### Añadir interfaz con VLANs TAG
```bash
tagging config {"action": "add", "name": "eth2", "vlan_untag": "", "vlan_tag": "10,20,30"}
```

#### Eliminar interfaz
```bash
tagging config {"action": "remove", "name": "eth1"}
```

#### Mostrar configuración
```bash
tagging config {"action": "show"}
```

**NOTA**: Una interfaz NO puede estar UNTAGGED en una VLAN Y TAGGED en otras simultáneamente.
          Debe elegir UNO de estos modos:
          - UNTAG: Acceso a una sola VLAN (vlan_untag: "10")
          - TAG:   Troncal con múltiples VLANs (vlan_tag: "10,20,30")

---

## 💡 Ejemplos de Sesión

### Sesión completa

```
$ nc localhost 2200
============================================================
JSBach V4.0 - CLI Management Interface
============================================================

Username: admin
Password: password123

✅ Autenticación exitosa. Bienvenido admin!

Escribe 'help' para ver los comandos disponibles.
Escribe 'exit' o 'quit' para salir.

jsbach@admin> vlans config {"action": "add", "id": 10, "name": "Oficina", "ip_interface": "192.168.10.1/24", "ip_network": "192.168.10.0/24"}

✅ ÉXITO
============================================================
VLAN 10 agregada
============================================================

jsbach@admin> vlans start

✅ ÉXITO
============================================================
VLANs iniciadas
============================================================

jsbach@admin> firewall enable_whitelist {"vlan_id": 10, "whitelist": ["8.8.8.8", "1.1.1.1"]}

✅ ÉXITO
============================================================
Whitelist habilitada en VLAN 10
============================================================

jsbach@admin> exit

👋 Cerrando sesión...
```

---

## 🔧 Arquitectura Técnica

### Componentes

1. **server.py**: Servidor TCP asyncio que escucha en puerto 2200
2. **session.py**: Gestiona sesiones individuales de clientes
3. **parser.py**: Analiza y valida comandos del usuario
4. **executor.py**: Ejecuta comandos usando `execute_module_action()`

### Integración

- Comparte `auth_helper.py` con la interfaz web
- Reutiliza `execute_module_action()` de `admin_router.py`
- Mismo sistema de logs que el resto del sistema

### Seguridad

- Autenticación obligatoria antes de ejecutar comandos
- Timeout de sesión: 300 segundos de inactividad
- Validación de comandos antes de ejecución
- Logs de todas las conexiones y comandos

---

## 🐛 Troubleshooting

### El puerto 2200 no responde

```bash
# Verificar que el servicio está corriendo
sudo systemctl status jsbach

# Verificar que el puerto está escuchando
sudo netstat -tlnp | grep 2200
```

### Autenticación falla

```bash
# Verificar archivo de usuarios
sudo cat /opt/JSBach_V4.0/config/cli_users.json

# Verificar permisos
ls -la /opt/JSBach_V4.0/config/cli_users.json
```

### Ver logs en tiempo real

```bash
sudo journalctl -u jsbach -f
```

### Abrir puerto en firewall

```bash
# UFW
sudo ufw allow 2200/tcp

# iptables
sudo iptables -A INPUT -p tcp --dport 2200 -j ACCEPT
```

---

## 📝 Notas Importantes

1. El CLI comparte el mismo sistema de autenticación que la web
2. Múltiples sesiones CLI pueden estar activas simultáneamente
3. Los comandos ejecutados vía CLI tienen los mismos efectos que en la web
4. Todas las acciones se registran en los logs del sistema
5. Los parámetros JSON deben estar correctamente formateados (comillas dobles)
6. Los cambios de configuración se aplican inmediatamente al hacer `start` o `restart`

---

**Documentación completa de comandos CLI - JSBach V4.0**
