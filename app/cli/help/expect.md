Modo de empleo: expect [ACCIÓN] [OPCIÓN]...

Gestiona la configuración de switches y dispositivos remotos mediante scripts interactivos.

Acciones:

  ### expect config
  Aplica configuraciones al dispositivo remoto. Soporta bloques separados por '/' para configurar múltiples grupos de puertos o configuraciones globales.
    --ip IP                    Dirección IP o Alias del switch (requerido)
    --actions ACCIONES         Configuraciones a aplicar (requerido)
    --profile PERFIL           ID del perfil de hardware (cisco_ios, tp_link)
    --dry-run                  (Flag) Muestra el script generado sin ejecutarlo

    Sintaxis de Acciones:
      "ports:<RANGO>,mode:<MODO>,<PARÁMETROS>..."
      
      Reglas de Jerarquía (IMPORTANTE):
      1. El parámetro 'mode' debe definirse ANTES de 'vlan', 'tag' o 'untag'.
      2. Modo 'access': solo acepta 'vlan'.
      3. Modo 'trunk'/'general': acepta 'tag' y 'untag'.

    Ejemplos:
      expect config --ip 192.168.1.10 --actions "hostname:CoreSwitch"
      expect config --ip 192.168.1.10 --actions "ports:1-12,mode:access,vlan:10 / ports:13-24,mode:trunk,tag:20-30"

  ### expect auth
  Gestiona las credenciales de acceso para un dispositivo específico.
    --ip IP                    Dirección IP del dispositivo (requerido)
    --user USUARIO             Nombre de usuario
    --password PASS            Contraseña de acceso

    Ejemplo:
      expect auth --ip 192.168.1.10 --user admin --password secret

  ### expect profile-mod
  Modifica parámetros de comportamiento de un perfil o IP específica.
    --ip IP                    Dirección IP del dispositivo (requerido)
    --auth-required BOL        Habilita o deshabilita el login obligatorio (true|false)

  ### expect reset
  Realiza un Soft Reset de todos los puertos del switch a su configuración predeterminada.
  NOTA: No borra la configuración IP de gestión ni usuarios, solo limpia las interfaces físicas.
    --ip IP                    Dirección IP del dispositivo (requerido)
    --profile PERFIL           ID del perfil de hardware (opcional, default: cisco_ios)

    Ejemplo:
      expect reset --ip 192.168.1.10 --profile tp_link

  ### expect port-security
  Configura Whitelists de MAC (Sticky/Static) en puertos específicos.
  Restringe el acceso físico al puerto, permitiendo solo las direcciónes MAC listadas.
    --ip IP                    Dirección IP del dispositivo (requerido)
    --ports PUERTOS            Lista de puertos (Ej: 1,2-4). NO USAR ESPACIOS. (requerido)
    --macs LISTA_MACS          MACs permitidas separadas por espacio o coma (requerido)
    --dry-run                  (Flag) Muestra el script generado sin ejecutarlo

    Ejemplos:
      expect port-security --ip 1.1.1.1 --ports 1 --macs AA:BB:CC:DD:EE:FF
      expect port-security --ip 1.1.1.1 --ports 1,2-4 --macs "AA:BB:CC:DD:EE:FF GG:HH:II:JJ:KK:LL"
      expect port-security --ip 1.1.1.1 --ports 1,2-4,5 --macs AA:BB:CC:DD:EE:FF

  ### expect status
  Muestra información sobre el estado del módulo, perfiles cargados y bloqueos activos.

Notas:
  - Jerarquía lógica: En bloques de puertos, se requiere definir el 'mode' antes de especificar vlan, tag o untag.
  - El parámetro 'vlan' solo es válido en modo 'access'.
  - Los modos 'trunk' o 'general' requieren el uso de 'tag' y/o 'untag'.
  - Use el separador '/' para definir múltiples bloques de configuración de forma secuencial.
  - Las contraseñas se almacenan con cifrado básico y permisos de sistema restringidos (600).
