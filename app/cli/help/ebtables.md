Modo de empleo: ebtables [ACCIÓN] [OPCIÓN]...

Filtrado de capa 2 (MAC) y aislamiento Private VLAN (PVLAN).

Acciones:

  ### ebtables status
  Muestra si las reglas de ebtables están activas y el estado de cada VLAN.

  ### ebtables start / stop / restart
  Gestiona la activación y desactivación global de las reglas de capa 2.

  ### ebtables aislar
  Activa PVLAN: los hosts de la VLAN solo pueden comunicarse con la WAN.
    --vlan_id ID               ID de la VLAN para aplicar aislamiento L2

  ### ebtables desaislar
  Desactiva el aislamiento de capa 2 en la VLAN.
    --vlan_id ID               ID de la VLAN

  ### ebtables add_mac
  Autoriza una dirección física en la VLAN 1 (Administración).
    --mac DIRECCIÓN            Formato XX:XX:XX:XX:XX:XX (requerido)

  ### ebtables remove_mac
  Elimina el acceso a una MAC previamente autorizada.
    --mac DIRECCIÓN            MAC que se desea quitar de la lista

  ### ebtables enable_whitelist
  Activa el filtrado estricto por MAC en la VLAN 1.

  ### ebtables disable_whitelist
  Permite el tráfico de cualquier MAC en la VLAN 1 (Inseguro).

  ### ebtables show_whitelist
  Lista todas las direcciones MAC autorizadas por el administrador.

Notas:
  - El filtrado por MAC es una funcionalidad exclusiva de la VLAN 1.
  - El aislamiento PVLAN previene ataques de red local como ARP Spoofing.
  - Requiere que las interfaces estén gestionadas por el módulo 'tagging'.
