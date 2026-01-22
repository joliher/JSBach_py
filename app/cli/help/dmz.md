# MÓDULO DMZ - JSBach V4.0

Zona desmilitarizada para servicios expuestos a Internet.

## COMANDOS DISPONIBLES

### dmz status
Ver el estado actual del DMZ y destinos configurados

Ejemplo:
  dmz status

### dmz config
Añadir un destino DMZ

Ejemplo:
  dmz config {"ip": "192.168.3.10", "port": 80, "protocol": "tcp"}

Parámetros:
  - ip: IP del servidor en la red local
  - port: Puerto del servicio
  - protocol: Protocolo (tcp o udp)

### dmz eliminar
Eliminar un destino DMZ

Ejemplo:
  dmz eliminar {"ip": "192.168.3.10", "port": 80, "protocol": "tcp"}

Parámetros:
  - ip: IP del destino
  - port: Puerto del servicio
  - protocol: Protocolo

### dmz start
Iniciar DMZ (aplicar reglas de port forwarding)

Ejemplo:
  dmz start

### dmz stop
Detener DMZ (eliminar reglas)

Ejemplo:
  dmz stop

### dmz restart
Reiniciar DMZ

Ejemplo:
  dmz restart

### dmz aislar
Aislar un destino (deshabilitar temporalmente)

Ejemplo:
  dmz aislar {"ip": "192.168.3.10", "port": 80, "protocol": "tcp"}

Parámetros:
  - ip: IP del destino
  - port: Puerto
  - protocol: Protocolo

### dmz desaislar
Desaislar un destino (restaurar)

Ejemplo:
  dmz desaislar {"ip": "192.168.3.10", "port": 80, "protocol": "tcp"}

Parámetros:
  - ip: IP del destino
  - port: Puerto
  - protocol: Protocolo

## FUNCIONAMIENTO

El DMZ permite exponer servicios de la red local a Internet mediante
port forwarding (DNAT - Destination NAT).

Ejemplo de uso típico:
  - Servidor web en 192.168.3.10:80
  - Se expone en la IP pública del router en el puerto 80
  - El tráfico externo al puerto 80 se redirige a 192.168.3.10:80

## NOTAS

- Cada destino DMZ se identifica por IP:Puerto:Protocolo
- Múltiples destinos pueden usar diferentes puertos
- El aislamiento permite deshabilitar temporalmente un destino sin eliminarlo
- DMZ requiere NAT configurado y activo
