# MÓDULO FIREWALL - JSBach V4.0

Gestión de reglas de seguridad y control de acceso por VLAN.

## COMANDOS DISPONIBLES

### firewall status
Ver el estado actual del firewall

Ejemplo:
  firewall status

### firewall start
Iniciar el firewall (aplicar reglas)

Ejemplo:
  firewall start

### firewall stop
Detener el firewall (eliminar reglas)

Ejemplo:
  firewall stop

### firewall restart
Reiniciar el firewall

Ejemplo:
  firewall restart

### firewall enable_whitelist
Habilitar whitelist en una VLAN

Ejemplo:
  firewall enable_whitelist {"vlan_id": 10, "whitelist": ["8.8.8.8", "1.1.1.1", "208.67.222.222"]}

Parámetros:
  - vlan_id: ID de la VLAN (número)
  - whitelist: Array de IPs permitidas

### firewall disable_whitelist
Deshabilitar whitelist en una VLAN

Ejemplo:
  firewall disable_whitelist {"vlan_id": 10}

Parámetros:
  - vlan_id: ID de la VLAN

### firewall add_rule
Añadir una IP a la whitelist de una VLAN

Ejemplo:
  firewall add_rule {"vlan_id": 10, "rule": "4.4.4.4"}

Parámetros:
  - vlan_id: ID de la VLAN
  - rule: IP a añadir

### firewall remove_rule
Eliminar una IP de la whitelist de una VLAN

Ejemplo:
  firewall remove_rule {"vlan_id": 10, "rule": "4.4.4.4"}

Parámetros:
  - vlan_id: ID de la VLAN
  - rule: IP a eliminar

### firewall aislar
Aislar una VLAN (sin acceso a Internet)

Ejemplo:
  firewall aislar {"vlan_id": 20}

Parámetros:
  - vlan_id: ID de la VLAN a aislar

### firewall desaislar
Desaislar una VLAN (restaurar acceso)

Ejemplo:
  firewall desaislar {"vlan_id": 20}

Parámetros:
  - vlan_id: ID de la VLAN a desaislar

## FUNCIONAMIENTO

El firewall gestiona el acceso a Internet por VLAN mediante:

1. **Whitelist**: Lista de IPs permitidas cuando está habilitada
   - Si está habilitada, SOLO las IPs en la whitelist pueden ser accedidas
   - Si está deshabilitada, se permite todo el tráfico

2. **Aislamiento**: Bloquea completamente el acceso a Internet de una VLAN
   - La VLAN queda sin acceso exterior
   - Mantiene comunicación interna dentro de la VLAN

## NOTAS

- Cada VLAN tiene su propia configuración de firewall
- Las reglas se aplican inmediatamente al ejecutar los comandos
- El aislamiento tiene prioridad sobre la whitelist
