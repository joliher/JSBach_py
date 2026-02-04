Modo de empleo: wan [ACCIÓN] [OPCIÓN]...

Gestiona la configuración de la interfaz de red externa (WAN).

Acciones:

  ### wan status
  Muestra el estado actual (IP, Máscara, GW) y la conectividad del enlace.

  ### wan config
  Establece los parámetros de red para la interfaz física.
    --mode MODO                MODO puede ser 'dhcp' o 'static' (requerido)
    --interface IFACE          Nombre de la interfaz (ej: eth0) (requerido)
    --ip IP                    Dirección IP estática (solo modo static)
    --netmask MASK             Máscara de subred (solo modo static)
    --gateway GW               Puerta de enlace (solo modo static)
    --dns DNS                  Servidores DNS (solo modo static)

    Ejemplos:
      wan config --mode dhcp --interface eth0
      wan config --mode static --interface eth0 --ip 1.1.1.1 --netmask 255.0.0.0

  ### wan start
  Levanta la interfaz y aplica las rutas y configuración DNS.

  ### wan stop
  Baja la interfaz y limpia las reglas de ruteo asociadas.

  ### wan restart
  Reinicia la conexión WAN para refrescar la configuración.

Notas:
  - Los cambios de configuración requieren un reinicio (restart) para aplicarse.
  - El modo DHCP obtiene automáticamente IP, Gateway y DNS del proveedor.
  - En modo estático, IP, máscara de red y puerta de enlace son obligatorios.
