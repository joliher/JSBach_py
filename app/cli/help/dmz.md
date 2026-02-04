Modo de empleo: dmz [ACCIÓN] [OPCIÓN]...

Gestión de redirección de puertos y protección de servidores expuestos.

Acciones:

  ### dmz status
  Lista los destinos (IP:Puerto:Protocolo) configurados y su estado de aislamiento.

  ### dmz config
  Crea una nueva regla de redirección de puerto (DNAT).
    --ip IP                    Dirección IP del servidor interno (requerido)
    --port PUERTO              Puerto de escucha (1-65535) (requerido)
    --protocol PROTO           Protocolo del servicio (tcp o udp) (requerido)

    Ejemplo:
      dmz config --ip 192.168.3.10 --port 80 --protocol tcp

  ### dmz eliminar
  Borra una redirección y limpia las reglas de protección asociadas.
    --ip IP                    IP del host
    --port PUERTO              Puerto del servicio
    --protocol PROTO           Protocolo del servicio

  ### dmz start
  Activa las reglas DNAT y permite el tráfico en la cadena FORWARD.

  ### dmz stop
  Limpia todas las redirecciones y cortafuegos asociados a la DMZ.

  ### dmz restart
  Reinicia el subsistema de redirección de puertos.

  ### dmz aislar
  Bloquea todo el tráfico bidireccional (WAN <-> Host y Host <-> Router).
    --ip IP                    Dirección IP del host a aislar (requerido)

  ### dmz desaislar
  Restaurar la conectividad normal del host en la DMZ.
    --ip IP                    Dirección IP del host a desaislar (requerido)

Notas:
  - El aislamiento DMZ protege proactivamente al router de hosts comprometidos.
  - Se validan las IPs privadas dentro de los rangos de las VLANs activas.
  - La redirección de puertos requiere que el módulo NAT esté activo.
