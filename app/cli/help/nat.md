Modo de empleo: nat [ACCIÓN] [OPCIÓN]...

Configuración de Masquerade para compartir conexión a Internet.

Acciones:

  ### nat status
  Muestra el estado del IP Forwarding y las reglas activas en la tabla NAT.

  ### nat config
  Define las interfaces para la traducción de direcciones.
    --wan_interface IFACE      Interfaz de salida (Internet) (requerido)
    --lan_interfaces IFACES    Interfaces locales (ej: eth1,eth2) (requerido)

    Ejemplo:
      nat config --wan_interface eth0 --lan_interfaces eth1

  ### nat start
  Activa el forwarding y aplica la regla de Masquerade en iptables.

  ### nat stop
  Desactiva el forwarding y limpia las reglas de la tabla NAT.

  ### nat restart
  Recarga la configuración NAT del sistema.

Notas:
  - Requiere que la interfaz WAN esté operativa.
  - El IP Forwarding se gestiona de forma global para todo el router.
