# Módulo EBTABLES - Aislamiento de VLANs a Nivel L2

## Descripción General

El módulo **ebtables** proporciona aislamiento de VLANs a nivel de capa 2 (enlace de datos) utilizando el framework ebtables de Linux. Este módulo permite controlar el tráfico entre VLANs y hacia la WAN, implementando políticas de seguridad a nivel de puente Ethernet.

### Características Principales

- **Aislamiento Inter-VLAN**: Bloquea el tráfico directo entre VLANs diferentes
- **Control de acceso a WAN**: Permite/deniega acceso de VLANs específicas a la interfaz WAN
- **Arquitectura jerárquica**: Utiliza cadenas personalizadas por VLAN para mejor organización
- **Integración completa**: Se sincroniza con módulos WAN, VLANs y Tagging
- **Gestión dinámica**: Aplica/remueve reglas sin reiniciar el sistema

### Dependencias

El módulo **ebtables** requiere que los siguientes módulos estén **ACTIVOS**:
- **WAN**: Para determinar la interfaz de salida a Internet
- **VLANs**: Para obtener la lista de VLANs configuradas
- **Tagging**: Para mapear interfaces físicas a VLANs

---

## Arquitectura

### Estructura de Cadenas

El módulo crea una arquitectura jerárquica de cadenas en ebtables:

```
FORWARD (cadena principal)
  ├─> VLAN_1 (cadena personalizada)
  │   ├─ Regla: Permitir hacia WAN
  │   ├─ Regla: Permitir entre interfaces de VLAN 1
  │   └─ Regla: DROP resto
  ├─> VLAN_2 (cadena personalizada)
  │   ├─ Regla: Denegar hacia WAN
  │   ├─ Regla: Permitir entre interfaces de VLAN 2
  │   └─ Regla: DROP resto
  └─> ...
```

### Flujo de Trabajo

1. **Validación de dependencias**: Verifica que WAN, VLANs y Tagging estén activos
2. **Sincronización de VLANs**: Lee configuración de vlans.json y ebtables.json
3. **Creación de cadenas**: Genera cadena personalizada por cada VLAN
4. **Aplicación de reglas**: Configura aislamiento según la configuración
5. **Actualización de estado**: Marca el módulo como activo/inactivo

---

## Archivo de Configuración

### Ubicación
```
/opt/JSBach_V4.0/config/ebtables/ebtables.json
```

### Estructura JSON
```json
{
    "vlans": {
        "10": {
            "id": 10,
            "name": "Oficina",
            "isolated": true,
            "allow_wan": false
        },
        "20": {
            "id": 20,
            "name": "Visitantes",
            "isolated": true,
            "allow_wan": true
        }
    },
    "status": 1
}
```

### Campos

| Campo | Tipo | Descripción |
|-------|------|-------------|
| `vlans` | object | Diccionario de VLANs con su configuración de aislamiento |
| `vlans.{id}` | object | Configuración específica de una VLAN |
| `vlans.{id}.id` | int | ID de la VLAN (debe coincidir con vlans.json) |
| `vlans.{id}.name` | string | Nombre descriptivo de la VLAN |
| `vlans.{id}.isolated` | bool | `true` = aislada, `false` = sin aislamiento |
| `vlans.{id}.allow_wan` | bool | `true` = permite acceso a WAN, `false` = bloquea WAN |
| `status` | int | Estado del módulo: `0` = inactivo, `1` = activo |

---

## Comandos Disponibles

### 1. `start` - Iniciar Ebtables

**Descripción**: Inicia el módulo ebtables, aplicando reglas de aislamiento a todas las VLANs configuradas.

**Sintaxis CLI**:
```bash
ebtables start
```

**Comportamiento**:
1. Valida que WAN, VLANs y Tagging estén activos
2. Limpia reglas previas de ebtables
3. Lee configuración de VLANs desde vlans.json
4. Crea cadenas personalizadas por VLAN
5. Aplica reglas de aislamiento según ebtables.json
6. Actualiza status a `1` (activo)

**Ejemplo de salida**:
```
Ebtables iniciado correctamente
VLANs aisladas:
  - VLAN 10: Aislada ✓ | Acceso WAN: No ✗
  - VLAN 20: Aislada ✓ | Acceso WAN: Sí ✓
```

**Errores comunes**:
- `"WAN no está activa"`: El módulo WAN debe estar iniciado primero
- `"VLANs no están activas"`: El módulo VLANs debe estar iniciado primero
- `"Tagging no está activo"`: El módulo Tagging debe estar iniciado primero
- `"No hay VLANs configuradas"`: Configura al menos una VLAN en vlans.json

---

### 2. `stop` - Detener Ebtables

**Descripción**: Detiene el módulo ebtables, eliminando todas las reglas y cadenas personalizadas.

**Sintaxis CLI**:
```bash
ebtables stop
```

**Comportamiento**:
1. Lee configuración de VLANs
2. Elimina reglas de aislamiento para cada VLAN
3. Elimina cadenas personalizadas (VLAN_X)
4. Actualiza status a `0` (inactivo)

**Ejemplo de salida**:
```
Ebtables detenido correctamente. Todas las reglas eliminadas.
```

**Nota**: Después de `stop`, todas las VLANs pueden comunicarse libremente (sin aislamiento).

---

### 3. `restart` - Reiniciar Ebtables

**Descripción**: Reinicia el módulo ebtables, equivalente a ejecutar `stop` seguido de `start`.

**Sintaxis CLI**:
```bash
ebtables restart
```

**Comportamiento**:
1. Ejecuta `stop` (limpia reglas)
2. Ejecuta `start` (recrea reglas)

**Uso recomendado**: Después de cambios en configuración de VLANs o Tagging.

---

### 4. `status` - Consultar Estado

**Descripción**: Muestra el estado actual del módulo ebtables y sus reglas activas.

**Sintaxis CLI**:
```bash
ebtables status
```

**Ejemplo de salida (activo)**:
```
Estado de Ebtables:
====================
Estado: 🟢 ACTIVO

VLANs configuradas:
  - VLAN 10 (Oficina):
      Aislada: Sí
      Acceso WAN: No
      Interfaces: eth1.10, eth2.10
  
  - VLAN 20 (Visitantes):
      Aislada: Sí
      Acceso WAN: Sí
      Interfaces: eth1.20

Dependencias:
  ✓ WAN: ACTIVA (eno1)
  ✓ VLANs: ACTIVAS (2 VLANs)
  ✓ Tagging: ACTIVO (2 interfaces)
```

**Ejemplo de salida (inactivo)**:
```
Estado de Ebtables:
====================
Estado: 🔴 INACTIVO

Para iniciar el módulo, ejecute: ebtables start
```

---

### 5. `aislar` - Aislar VLAN

**Descripción**: Aplica aislamiento a una VLAN específica. Bloquea tráfico inter-VLAN y opcionalmente hacia WAN.

**Sintaxis CLI**:
```bash
ebtables aislar vlan_id=<ID> allow_wan=<true|false>
```

**Parámetros**:
| Parámetro | Tipo | Requerido | Descripción |
|-----------|------|-----------|-------------|
| `vlan_id` | int | Sí | ID de la VLAN a aislar (debe existir en vlans.json) |
| `allow_wan` | bool | No | `true` = permite WAN, `false` = bloquea WAN (default: `false`) |

**Ejemplos**:

Aislar VLAN 10 sin acceso a WAN:
```bash
ebtables aislar vlan_id=10 allow_wan=false
```

Aislar VLAN 20 con acceso a WAN:
```bash
ebtables aislar vlan_id=20 allow_wan=true
```

**Comportamiento**:
1. Valida que la VLAN exista en vlans.json
2. Valida que ebtables esté activo
3. Crea cadena personalizada VLAN_X si no existe
4. Aplica reglas de aislamiento:
   - Permite tráfico entre interfaces de la misma VLAN
   - Permite/deniega acceso a WAN según `allow_wan`
   - Bloquea tráfico hacia otras VLANs
5. Actualiza ebtables.json con la configuración

**Ejemplo de salida**:
```
VLAN 10 aislada correctamente
  - Aislamiento inter-VLAN: Activo
  - Acceso a WAN: Denegado
  - Interfaces aisladas: eth1.10, eth2.10
```

**Errores comunes**:
- `"VLAN X no existe"`: La VLAN no está configurada en vlans.json
- `"Ebtables no está activo"`: Ejecuta `ebtables start` primero
- `"Error al crear cadena"`: Verifica permisos de root

---

### 6. `desaislar` - Remover Aislamiento

**Descripción**: Remueve el aislamiento de una VLAN específica, permitiendo comunicación libre.

**Sintaxis CLI**:
```bash
ebtables desaislar vlan_id=<ID>
```

**Parámetros**:
| Parámetro | Tipo | Requerido | Descripción |
|-----------|------|-----------|-------------|
| `vlan_id` | int | Sí | ID de la VLAN a desaislar |

**Ejemplo**:
```bash
ebtables desaislar vlan_id=10
```

**Comportamiento**:
1. Valida que ebtables esté activo
2. Elimina reglas de aislamiento de la VLAN
3. Elimina cadena personalizada VLAN_X
4. Actualiza ebtables.json (marca `isolated: false`)

**Ejemplo de salida**:
```
VLAN 10 desaislada correctamente. Tráfico libre permitido.
```

---

## Reglas de Ebtables Aplicadas

### Reglas por VLAN Aislada (allow_wan = false)

```bash
# Ejemplo para VLAN 10 sin acceso a WAN

# 1. Salto a cadena personalizada
ebtables -A FORWARD -i eth1.10 -j VLAN_10
ebtables -A FORWARD -i eth2.10 -j VLAN_10

# 2. Dentro de la cadena VLAN_10:
# Bloquear acceso a WAN
ebtables -A VLAN_10 -o eno1 -j DROP

# Permitir tráfico entre interfaces de la misma VLAN
ebtables -A VLAN_10 -o eth1.10 -j ACCEPT
ebtables -A VLAN_10 -o eth2.10 -j ACCEPT

# Bloquear todo lo demás (otras VLANs)
ebtables -A VLAN_10 -j DROP
```

### Reglas por VLAN Aislada (allow_wan = true)

```bash
# Ejemplo para VLAN 20 con acceso a WAN

# 1. Salto a cadena personalizada
ebtables -A FORWARD -i eth1.20 -j VLAN_20

# 2. Dentro de la cadena VLAN_20:
# Permitir acceso a WAN
ebtables -A VLAN_20 -o eno1 -j ACCEPT

# Permitir tráfico entre interfaces de la misma VLAN
ebtables -A VLAN_20 -o eth1.20 -j ACCEPT

# Bloquear todo lo demás (otras VLANs)
ebtables -A VLAN_20 -j DROP
```

---

## Logs del Módulo

### Ubicación
```
/opt/JSBach_V4.0/logs/ebtables/actions.log
```

### Formato
```
DD/MM/YYYY HH:MM:SS - LEVEL - acción - ESTADO: mensaje
```

### Ejemplos de Logs

```
02/02/2026 20:55:10 - INFO - start - SUCCESS: Ebtables iniciado. 2 VLANs aisladas
02/02/2026 20:56:15 - INFO - aislar - SUCCESS: VLAN 10 aislada (WAN: No)
02/02/2026 20:57:22 - INFO - desaislar - SUCCESS: VLAN 10 desaislada
02/02/2026 20:58:00 - ERROR - start - ERROR: Dependencias no cumplidas. WAN no está activa
02/02/2026 20:59:12 - INFO - stop - SUCCESS: Ebtables detenido. Todas las reglas eliminadas
```

---

## Casos de Uso

### Caso 1: Aislar VLAN de Invitados (solo acceso a Internet)

**Objetivo**: Los invitados pueden acceder a Internet pero no a recursos internos.

**Configuración**:
1. Crear VLAN de invitados:
```bash
vlans config action=add id=100 name=Invitados ip=10.100.1.1 netmask=255.255.255.0
vlans start
```

2. Configurar tagging en interfaces:
```bash
tagging config action=add interface=eth1 vlan_tag=100
tagging start
```

3. Aislar VLAN con acceso a WAN:
```bash
ebtables start
ebtables aislar vlan_id=100 allow_wan=true
```

**Resultado**: VLAN 100 puede acceder a Internet (WAN) pero no a otras VLANs internas.

---

### Caso 2: Aislar VLAN de Servidores (sin acceso a Internet)

**Objetivo**: Servidores internos aislados completamente, sin salida a Internet.

**Configuración**:
```bash
# Crear VLAN de servidores
vlans config action=add id=50 name=Servidores ip=10.50.1.1 netmask=255.255.255.0
vlans start

# Aislar sin acceso a WAN
ebtables start
ebtables aislar vlan_id=50 allow_wan=false
```

**Resultado**: VLAN 50 no puede acceder a Internet ni a otras VLANs.

---

### Caso 3: Segmentación Completa de Red

**Objetivo**: Múltiples VLANs aisladas con diferentes políticas de acceso a WAN.

**Configuración**:
```bash
# Iniciar ebtables
ebtables start

# VLAN 10 (Administración) - Sin acceso a WAN
ebtables aislar vlan_id=10 allow_wan=false

# VLAN 20 (Empleados) - Con acceso a WAN
ebtables aislar vlan_id=20 allow_wan=true

# VLAN 30 (DMZ) - Con acceso a WAN
ebtables aislar vlan_id=30 allow_wan=true

# VLAN 100 (Invitados) - Solo acceso a WAN
ebtables aislar vlan_id=100 allow_wan=true
```

---

## Integración con Otros Módulos

### Firewall
El módulo **ebtables** trabaja en capa 2, mientras que **firewall** opera en capa 3. Ambos pueden coexistir:
- **ebtables**: Controla tráfico a nivel de puente Ethernet (MAC addresses)
- **firewall**: Controla tráfico a nivel de IP (iptables)

Recomendación: Usar ebtables para aislamiento de VLANs y firewall para reglas específicas de IPs.

### NAT
NAT opera después de ebtables. Si una VLAN tiene `allow_wan=true`, el tráfico puede ser traducido por NAT.

### DMZ
DMZ puede redirigir tráfico a VLANs aisladas. Configura ebtables para permitir acceso WAN en VLANs con servidores DMZ.

---

## Troubleshooting

### Problema: "Dependencias no cumplidas"

**Causa**: WAN, VLANs o Tagging no están activos.

**Solución**:
```bash
# Verificar estado
wan status
vlans status
tagging status

# Iniciar módulos faltantes
wan start
vlans start
tagging start

# Reintentar ebtables
ebtables start
```

---

### Problema: "VLAN X no existe en configuración"

**Causa**: La VLAN no está configurada en vlans.json.

**Solución**:
```bash
# Verificar VLANs configuradas
vlans status

# Agregar VLAN faltante
vlans config action=add id=X name=NombreVLAN ip=10.X.1.1 netmask=255.255.255.0
vlans restart

# Reintentar aislamiento
ebtables aislar vlan_id=X allow_wan=true
```

---

### Problema: Tráfico entre VLANs aún funciona después de aislar

**Causa**: Posiblemente hay routing a nivel IP o ebtables no está activo.

**Solución**:
```bash
# Verificar estado de ebtables
ebtables status

# Listar reglas activas
ebtables -L --Lc

# Reiniciar módulo
ebtables restart
```

---

### Problema: No hay acceso a Internet después de aislar con allow_wan=true

**Causa**: NAT o WAN puede tener problemas.

**Solución**:
```bash
# Verificar WAN
wan status

# Verificar NAT
nat status

# Verificar reglas de ebtables
ebtables -L VLAN_X

# Desaislar temporalmente para diagnosticar
ebtables desaislar vlan_id=X
```

---

## Comandos de Diagnóstico

### Ver todas las reglas de ebtables
```bash
ebtables -L --Lc
```

### Ver reglas de una cadena específica
```bash
ebtables -L VLAN_10 --Lc
```

### Ver estadísticas de paquetes
```bash
ebtables -L VLAN_10 --Lc --Ln
```

### Limpiar manualmente todas las reglas
```bash
ebtables -F
ebtables -X
```

---

## Notas de Seguridad

1. **Permisos root**: Ebtables requiere privilegios de superusuario
2. **Persistencia**: Las reglas se pierden al reiniciar. Use `ebtables start` en el arranque
3. **Verificación**: Siempre ejecute `status` después de cambios para validar configuración
4. **Backup**: Mantenga respaldos de ebtables.json antes de cambios masivos

---

## Referencias

- Documentación oficial de ebtables: http://ebtables.netfilter.org/
- Integración con VLANs: Ver `/app/cli/help/vlans.md`
- Integración con Tagging: Ver `/app/cli/help/tagging.md`
- Logs del sistema: `/opt/JSBach_V4.0/logs/ebtables/actions.log`
