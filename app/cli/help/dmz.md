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

Funcionalidad:
  - Elimina el destino de la configuración
  - Si el destino estaba aislado, elimina automáticamente:
    • Regla RETURN de PREROUTING_PROTECTION (nat table)
    • Regla DROP de INPUT (filter table)
  - Limpieza completa sin reglas huérfanas

### dmz start
Iniciar DMZ (aplicar reglas de port forwarding)

Ejemplo:
  dmz start

### dmz stop
Detener DMZ (eliminar todas las reglas)

Ejemplo:
  dmz stop

Funcionalidad:
  - Elimina todas las reglas DNAT (port forwarding)
  - Elimina reglas ACCEPT de FORWARD_VLAN_X
  - Elimina reglas de aislamiento de hosts aislados:
    • Reglas RETURN de PREROUTING_PROTECTION (nat table)
    • Reglas DROP de INPUT (filter table)
  - Elimina cadenas PREROUTING_VLAN_X
  - Limpieza completa del módulo DMZ

### dmz restart
Reiniciar DMZ

Ejemplo:
  dmz restart

### dmz aislar
Aislar un host DMZ completamente (bloqueo bidireccional)

Ejemplo:
  dmz aislar {"ip": "10.0.5.50"}

Parámetros:
  - ip: IP del host DMZ a aislar

Funcionalidad:
  - Inserta RETURN en PREROUTING_PROTECTION posición 1 (nat table, -d IP)
    → Bloquea DNAT hacia el host (impide port forwarding)
    → El paquete sale de PREROUTING sin aplicar redirección
  - Inserta DROP en INPUT posición 1 (filter table, -s IP)
    → Bloquea tráfico DESDE el host hacia el router
  - Aislamiento COMPLETO en etapa PREROUTING (antes de routing)
  - PREROUTING_PROTECTION tiene prioridad sobre PREROUTING_VLAN_X
  - Útil para contener hosts comprometidos inmediatamente
  - Prioridad MÁXIMA: el aislamiento ocurre ANTES de DNAT

Cadenas utilizadas:
  - PREROUTING_PROTECTION (nat, posición 1 en PREROUTING)
  - INPUT (filter, posición 1 para bloqueo desde host)

### dmz desaislar
Desaislar un host DMZ (restaurar conectividad)

Ejemplo:
  dmz desaisRETURN de PREROUTING_PROTECTION (nat table)
  - Elimina DROP de INPUT (filter table)
  - Restaura funcionalidad normal del host DMZ
  - Las reglas DNAT vuelven a aplicarse correctamente
  - ip: IP del host DMZ a desaislar

Funcionalidad:
  - Elimina DROP de FORWARD_PROTECTION
  - Elimina DROP de INPUT
  - Restaura funcionalidad normal del host DMZ

## FUNCIONAMIENTO

El DMZ permite exponer servicios de la red local a Internet mediante
port forwarding (DNAT - Destination NAT).

Ejemplo de uso típico:
  - Servidor web en 192.168.3.10:80
  - Se expone en la IP pública del router en el puerto 80
  - El tráfico externo al puerto 80 se redirige a 192.168.3.10:80

## VALIDACIONES

Al añadir un host DMZ, se valida que:
- La IP sea válida y privada (RFC1918)
- La IP esté dentro del rango de la VLAN (ip_network)
- La IP NO sea la dirección de red (terminada en .0)
- La IP NO sea la dirección de broadcast (terminada en .255)
- La IP NO sea el gateway de la VLAN
- La IP NO contenga máscara de red (/24, /16, etc.)
- El puerto esté usa PREROUTING_PROTECTION (nat table) para bloquear ANTES de DNAT
- PREROUTING_PROTECTION está en posición 1 de PREROUTING (máxima prioridad)
- Al eliminar un destino aislado, las reglas se limpian automáticamente
- Al ejecutar 'dmz stop', se eliminan todas las reglas incluyendo aislamientos
- DMZ requiere Firewall y VLANs configurados y activos

## ARQUITECTURA DE AISLAMIENTO

El aislamiento DMZ utiliza una arquitectura en dos capas:

1. **PREROUTING_PROTECTION (nat table)**:
   - Posición 1 en PREROUTING
   - Acción: RETURN (sale de cadena sin aplicar DNAT)
   - Bloquea WAN → DMZ (impide port forwarding)
   - Ejecuta ANTES que PREROUTING_VLAN_X

2. **INPUT (filter table)**:
   - Posición 1 en INPUT
   - Acción: DROP
   - Bloquea DMZ → Router
   - Impide que el host acceda al router directamente

Esta arquitectura es independiente del módulo Firewall:
- Firewall usa: FORWARD_PROTECTION, INPUT_PROTECTION (filter table)
- DMZ usa: PREROUTING_PROTECTION (nat table)
- No hay interferencia entre módulos

- Cada destino DMZ se identifica por IP:Puerto:Protocolo
- Múltiples destinos pueden usar diferentes puertos en la misma IP
- El aislamiento bloquea COMPLETAMENTE un host (FORWARD + INPUT)
- Al eliminar un destino aislado, las reglas se limpian automáticamente
- Al ejecutar 'dmz stop', se eliminan todas las reglas incluyendo aislamientos
- DMZ requiere NAT configurado y activo
