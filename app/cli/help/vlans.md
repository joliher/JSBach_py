Modo de empleo: vlans [ACCIÓN] [OPCIÓN]...

Creación y gestión de redes virtuales (VLANs).

Acciones:

  ### vlans status
  Ver el listado de VLANs creadas y su estado operacional.

  ### vlans config
  Administra la configuración persistente de las redes virtuales.
    --action add               Añadir una VLAN nueva
      --id ID                  VLAN ID (1-4094, único) (requerido)
      --name NOMBRE            Nombre descriptivo
      --ip_interface IP/MASK   IP del gateway (ej: 192.168.10.1/24)
      --ip_network RED/MASK    Red de la VLAN (ej: 192.168.10.0/24)

    --action remove            Borrar una VLAN de la base de datos
      --id ID                  ID de la VLAN a eliminar (requerido)

    --action show              Lista la configuración guardada por pantalla

  ### vlans start
  Despliega las interfaces virtuales (vlan.X) y asigna IPs en el sistema.

  ### vlans stop
  Detiene y elimina las interfaces virtuales del kernel.

  ### vlans restart
  Recarga toda la segmentación de red.

Notas:
  - Es obligatorio usar el formato CIDR (IP/Máscara) en las direcciones.
  - Se recomienda no usar VLAN IDs reservados por el hardware (ej: 0, 4095).
