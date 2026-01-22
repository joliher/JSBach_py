# MÓDULO TAGGING - JSBach V4.0

Etiquetado de tráfico VLAN en interfaces físicas.

## COMANDOS DISPONIBLES

### tagging status
Ver el estado actual del tagging

Ejemplo:
  tagging status

### tagging config
Configurar tagging en interfaces (añadir, eliminar, mostrar)

Añadir interfaz con VLAN UNTAG:
  tagging config {"action": "add", "name": "eth1", "vlan_untag": "10", "vlan_tag": ""}

Añadir interfaz con VLANs TAG:
  tagging config {"action": "add", "name": "eth2", "vlan_untag": "", "vlan_tag": "10,20,30"}

Añadir interfaz mixta (UNTAG + TAG):
  tagging config {"action": "add", "name": "eth3", "vlan_untag": "10", "vlan_tag": "20,30"}

Eliminar interfaz:
  tagging config {"action": "remove", "name": "eth1"}

Mostrar configuración:
  tagging config {"action": "show"}

Parámetros:
  - action: "add", "remove" o "show"
  - name: Nombre de la interfaz física
  - vlan_untag: VLAN sin etiquetar (una sola VLAN)
  - vlan_tag: VLANs etiquetadas (lista separada por comas)

### tagging start
Iniciar tagging (aplicar configuración)

Ejemplo:
  tagging start

### tagging stop
Detener tagging

Ejemplo:
  tagging stop

### tagging restart
Reiniciar tagging

Ejemplo:
  tagging restart

## CONCEPTOS

### VLAN UNTAG (Access Port)
  - Tráfico sin etiquetar en la interfaz
  - Los dispositivos conectados no ven las etiquetas VLAN
  - Solo UNA VLAN puede ser UNTAG por interfaz
  - Uso típico: Conectar dispositivos normales (PCs, impresoras)

### VLAN TAG (Trunk Port)
  - Tráfico etiquetado (IEEE 802.1Q)
  - Múltiples VLANs en la misma interfaz física
  - Los dispositivos deben soportar VLANs
  - Uso típico: Conectar switches, routers, servidores

## EJEMPLOS DE CONFIGURACIÓN

### Puerto de acceso (PC normal):
  tagging config {"action": "add", "name": "eth1", "vlan_untag": "10", "vlan_tag": ""}
  - El PC en eth1 estará en VLAN 10
  - No necesita configuración especial de VLAN

### Puerto troncal (switch):
  tagging config {"action": "add", "name": "eth2", "vlan_untag": "", "vlan_tag": "10,20,30"}
  - El switch recibirá tráfico de VLANs 10, 20 y 30 etiquetado
  - El switch debe soportar VLANs

### Puerto híbrido:
  tagging config {"action": "add", "name": "eth3", "vlan_untag": "10", "vlan_tag": "20,30"}
  - VLAN 10 sin etiquetar (para dispositivos normales)
  - VLANs 20 y 30 etiquetadas (para dispositivos avanzados)

## NOTAS

- Las interfaces deben existir en el sistema
- El tagging requiere que las VLANs estén creadas primero
- Cambios en la configuración requieren reiniciar el servicio
- No todos los switches soportan VLANs (verificar compatibilidad)
