# MÓDULO VLANS - JSBach V4.0

Creación y gestión de redes virtuales (VLANs).

## COMANDOS DISPONIBLES

### vlans status
Ver el estado actual de las VLANs

Ejemplo:
  vlans status

### vlans config
Configurar VLANs (añadir, eliminar, mostrar)

Añadir VLAN:
  vlans config {"action": "add", "id": 10, "name": "Oficina", "ip_interface": "192.168.10.1/24", "ip_network": "192.168.10.0/24"}

Eliminar VLAN:
  vlans config {"action": "remove", "id": 10}

Mostrar configuración:
  vlans config {"action": "show"}

Parámetros para añadir:
  - action: "add"
  - id: ID de la VLAN (1-4094)
  - name: Nombre descriptivo
  - ip_interface: IP del router en la VLAN (formato CIDR)
  - ip_network: Red de la VLAN (formato CIDR)

### vlans start
Iniciar VLANs (crear interfaces virtuales)

Ejemplo:
  vlans start

### vlans stop
Detener VLANs (eliminar interfaces)

Ejemplo:
  vlans stop

### vlans restart
Reiniciar VLANs

Ejemplo:
  vlans restart

## FUNCIONAMIENTO

Las VLANs permiten segmentar la red en múltiples redes lógicas independientes.

Cada VLAN tiene:
  - ID único (VLAN ID)
  - Nombre descriptivo
  - Subred IP propia
  - Interfaz virtual (vlan.X)

Ejemplo de configuración típica:
  - VLAN 10: Oficina (192.168.10.0/24)
  - VLAN 20: Invitados (192.168.20.0/24)
  - VLAN 30: IoT (192.168.30.0/24)

## NOTAS

- Las VLANs deben tener IDs únicos
- Cada VLAN debe tener una subred IP diferente
- El formato CIDR es obligatorio (ej: 192.168.10.1/24)
- Las VLANs requieren tagging en las interfaces físicas para funcionar
