Modo de empleo: firewall [ACCIÓN] [OPCIÓN]...

Gestión de reglas de seguridad e iptables por VLAN.

Acciones:

  ### firewall status
  Ver el estado actual del firewall, cadenas activas y estadísticas de iptables.

  ### firewall start
  Crea las cadenas necesarias y aplica todas las reglas de filtrado configuradas.

  ### firewall stop
  Elimina todas las reglas de filtrado y limpia las cadenas personalizadas.

  ### firewall restart
  Reinicia completamente el subsistema de firewall (stop + start).

  ### firewall enable_whitelist
  Habilita el filtrado restrictivo por lista blanca en una VLAN.
    --vlan_id ID               ID de la VLAN (número) (requerido)
    --whitelist IPS            Lista de IPs permitidas separadas por comas

  ### firewall disable_whitelist
  Desactiva la whitelist para la VLAN, permitiendo todo el tráfico.
    --vlan_id ID               ID de la VLAN (requerido)

  ### firewall add_rule
  Añade una IP individual a la whitelist de una VLAN existente.
    --vlan_id ID               ID de la VLAN (requerido)
    --rule IP                  IP que se desea autorizar (requerido)

  ### firewall remove_rule
  Elimina una IP de la whitelist, denegando su acceso.
    --vlan_id ID               ID de la VLAN (requerido)
    --rule IP                  IP que se desea bloquear (requerido)

  ### firewall aislar
  Bloquea todo el acceso a Internet (FORWARD) para una red local.
    --vlan_id ID               ID de la VLAN (requerido)

  ### firewall desaislar
  Restaura el acceso a Internet (sujeto a la configuración de whitelist).
    --vlan_id ID               ID de la VLAN (requerido)

  ### firewall restrict
  Protege el router limitando servicios (solo DNS/DHCP/ICMP) en la cadena INPUT.
    --vlan_id ID               ID de la VLAN (requerido)

  ### firewall unrestrict
  Elimina las restricciones de acceso al router para la VLAN especificada.
    --vlan_id ID               ID de la VLAN (requerido)

Notas:
  - El aislamiento (aislar) tiene prioridad máxima sobre el forwarding.
  - Las restricciones (restrict) afectan solo al tráfico dirigido a la IP del router.
  - Se recomienda verificar el estado con 'firewall status' tras aplicar cambios.
