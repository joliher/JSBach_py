Modo de empleo: tagging [ACCIÓN] [OPCIÓN]...

Etiquetado de tráfico IEEE 802.1Q en puertos físicos.

Acciones:

  ### tagging status
  Ver el mapeo actual de interfaces físicas y sus puentes (bridges) de red.

  ### tagging config
  Asocia una interfaz de hardware con una o varias VLANs.
    --action add               Configurar una interfaz física
      --name IFACE             Nombre de la interfaz (ej: eth1) (requerido)
      --vlan_untag ID          VLAN de acceso (Access Port, sin etiqueta)
      --vlan_tag IDS           VLANs troncales (Trunk Port, separadas por coma)

    --action remove            Desasociar una interfaz del sistema de tagging
      --name IFACE             Nombre de la interfaz (requerido)

    --action show              Mostrar configuración técnica de puentes

  ### tagging start
  Crea los bridges necesarios y activa el etiquetado en las interfaces físicas.

  ### tagging stop
  Desmonta los puentes y restaura las interfaces físicas al estado normal.

  ### tagging restart
  Recarga la topología de red de capa 2.

Conceptos:
  Access (Untagged)          Para dispositivos finales. Tráfico sin etiquetas.
  Trunk (Tagged)             Para switches/servidores. Mantiene etiquetas 802.1Q.

Notas:
  - Una interfaz debe elegirse como Acceso O como Troncal (no ambos).
  - Las VLANs deben estar previamente iniciadas con el módulo 'vlans'.
