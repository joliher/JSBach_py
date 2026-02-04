Modo de empleo: help [MÓDULO] [ACCIÓN]

Manual de referencia para la interfaz de comandos (CLI) de JSBach V4.0.

Descripción:
  La CLI de JSBach permite gestionar todos los subsistemas del router mediante
  un shell interactivo o comandos directos vía TCP (puerto 2200).

Conexión:
  nc localhost 2200          Conectar desde la propia máquina
  nc <ip-router> 2200        Conectar de forma remota

Sintaxis de comandos:
  <módulo> <acción> [--clave valor ...]

Módulos disponibles:
  wan                        Interfaz de salida a Internet
  nat                        Traducción de direcciones (Masquerade)
  firewall                   Filtrado de paquetes y seguridad por VLAN
  dmz                        Redirección de puertos y servicios expuestos
  vlans                      Segmentación de redes virtuales
  tagging                    Configuración de puertos Access y Trunk
  ebtables                   Filtrado de capa 2 y aislamiento MAC

Comandos especiales:
  help                       Muestra esta ayuda general
  help <módulo>              Detalla las acciones de un componente específico
  help <módulo> <acción>     Documentación detallada de un comando concreto
  exit / quit                Cierra la sesión y desconecta del puerto 2200

Ejemplos de sesión:
  1. Identificarse con usuario y contraseña (SHA256).
  2. Consultar estado: 'wan status', 'vlans status'.
  3. Aplicar cambios: 'firewall aislar --vlan_id 10'.
  4. Salir: 'exit'.

Notas:
  - Todas las acciones se registran en los archivos de log del sistema.
  - La sesión caduca a los 300 segundos de inactividad.
  - El sistema de colores resalta en verde los parámetros y en blanco los valores.
  - Se recomienda consultar la ayuda de cada módulo para conocer sus opciones.
