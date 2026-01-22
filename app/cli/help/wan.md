# MÓDULO WAN - JSBach V4.0

Gestiona la configuración de la interfaz de red externa (WAN).

## COMANDOS DISPONIBLES

### wan status
Ver el estado actual de la interfaz WAN

Ejemplo:
  wan status

### wan config
Configurar la interfaz WAN

Con DHCP:
  wan config {"mode": "dhcp", "interface": "eth0"}

Con IP estática:
  wan config {"mode": "static", "interface": "eth0", "ip": "192.168.1.100", "netmask": "255.255.255.0", "gateway": "192.168.1.1", "dns": ["8.8.8.8", "8.8.4.4"]}

### wan start
Iniciar la interfaz WAN

Ejemplo:
  wan start

### wan stop
Detener la interfaz WAN

Ejemplo:
  wan stop

### wan restart
Reiniciar la interfaz WAN

Ejemplo:
  wan restart

## PARÁMETROS

### mode
  - dhcp: Configuración automática vía DHCP
  - static: Configuración manual con IP estática

### interface (requerido)
  - Nombre de la interfaz de red (ej: eth0, eno1, enp0s3)

### ip (modo static)
  - Dirección IP estática

### netmask (modo static)
  - Máscara de red

### gateway (modo static)
  - Puerta de enlace predeterminada

### dns (modo static)
  - Lista de servidores DNS (array de IPs)

## NOTAS

- Los cambios de configuración requieren reiniciar la interfaz (restart o stop + start)
- El modo DHCP obtiene automáticamente IP, gateway y DNS
- En modo static, todos los parámetros son obligatorios
