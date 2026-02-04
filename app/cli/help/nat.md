# MÓDULO NAT - JSBach V4.0

Network Address Translation para compartir conexión a Internet.

## COMANDOS DISPONIBLES

### nat status
Ver el estado actual del NAT

Ejemplo:
  nat status


### nat config
Configurar NAT

Ejemplo (recomendado):
  nat config --wan_interface eth0 --lan_interfaces eth1,eth2

Para arrays complejos (legacy compatible):
  nat config --params '{"wan_interface": "eth0", "lan_interfaces": ["eth1", "eth2"]}'

Parámetros:
  - --wan_interface: Interfaz de salida a Internet
  - --lan_interfaces: Lista separada por comas de interfaces de red local (ej: eth1,eth2)

### nat start
Iniciar NAT (activar iptables rules)

Ejemplo:
  nat start

### nat stop
Detener NAT (desactivar iptables rules)

Ejemplo:
  nat stop

### nat restart
Reiniciar NAT

Ejemplo:
  nat restart

## FUNCIONAMIENTO

El módulo NAT permite que múltiples dispositivos en la red local compartan
una única conexión a Internet mediante traducción de direcciones.


Configuración típica:
  nat config --wan_interface eth0 --lan_interfaces eth1,eth2
  nat start
  nat status

  - WAN (eth0): Conexión a Internet
  - LAN (eth1, eth2, ...): Interfaces de red local

## NOTAS

- El NAT requiere que la interfaz WAN esté configurada y activa
- Se activa IP forwarding automáticamente
- Las reglas de iptables se configuran en la tabla NAT (POSTROUTING)
