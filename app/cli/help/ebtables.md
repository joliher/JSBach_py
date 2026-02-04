# Módulo EBTABLES - PVLAN y MAC Whitelist

## Descripción General

El módulo **ebtables** proporciona:
- **PVLAN (Private VLAN)**: Aislamiento de VLANs a nivel de capa 2
- **MAC Whitelist**: Control granular de acceso por dirección MAC en VLAN 1

Utiliza el framework ebtables de Linux para filtrado a nivel de enlace de datos.

### Características Principales

- **PVLAN**: Aislamiento total de VLANs (solo comunicación con WAN)
- **MAC Whitelist (VLAN 1)**: Control de acceso por dirección MAC
- **Arquitectura jerárquica**: Cadenas personalizadas `FORWARD_VLAN_X`
- **Integración completa**: Sincronización con WAN, VLANs y Tagging
- **Gestión dinámica**: Aplicación de reglas sin reiniciar

### Dependencias

El módulo requiere que estén **ACTIVOS**:
- **WAN**: Interfaz de salida a Internet
- **VLANs**: Configuración de redes VLAN
- **Tagging**: Mapeo de interfaces físicas a VLANs

---

## Comandos CLI

### Comandos Básicos

```bash
ebtables status     # Ver estado del módulo
ebtables start      # Iniciar módulo
ebtables stop       # Detener módulo
ebtables restart    # Reiniciar módulo
```

### PVLAN (Aislamiento de VLANs)

#### Aislar VLAN (Activar PVLAN)
```bash
ebtables aislar --vlan_id <ID>
```

**Ejemplo:**
```bash
ebtables aislar --vlan_id 2
```

**Efecto:** Solo permite comunicación con WAN, bloquea tráfico entre hosts de la misma VLAN.

#### Desaislar VLAN (Desactivar PVLAN)
```bash
ebtables desaislar --vlan_id <ID>
```

**Ejemplo:**
```bash
ebtables desaislar --vlan_id 2
```

### MAC Whitelist (Solo VLAN 1)

#### Agregar MAC
```bash
ebtables add_mac --mac <MAC_ADDRESS>
```

**Ejemplos:**
```bash
ebtables add_mac --mac AA:BB:CC:DD:EE:FF
ebtables add_mac --mac aa-bb-cc-dd-ee-ff
```

**Notas:**
- Formatos aceptados: `AA:BB:CC:DD:EE:FF` o `AA-BB-CC-DD-EE-FF`
- Se normaliza automáticamente a mayúsculas con dos puntos
- Se puede agregar MACs con whitelist deshabilitada

#### Eliminar MAC
```bash
ebtables remove_mac --mac <MAC_ADDRESS>
```

**Ejemplo:**
```bash
ebtables remove_mac --mac AA:BB:CC:DD:EE:FF
```

#### Habilitar Whitelist
```bash
ebtables enable_whitelist
```

**Efecto:** Solo las MACs en la lista pueden comunicarse. Habilitada por defecto.

#### Deshabilitar Whitelist
```bash
ebtables disable_whitelist
```

**Advertencia:** Todas las MACs podrán comunicarse sin restricciones.

#### Mostrar Whitelist
```bash
ebtables show_whitelist
```

Muestra:
- Estado (habilitada/deshabilitada)
- Lista de MACs
- Total de entradas

---

## Arquitectura Técnica

### Estructura de Cadenas

```
FORWARD (cadena principal)
  ├─> Redirección: -i eth1.1 -j FORWARD_VLAN_1
  ├─> Redirección: -i eth1.2 -j FORWARD_VLAN_2
  └─> ...

FORWARD_VLAN_1 (VLAN 1 - Admin)
  ├─> WAN rules (si PVLAN activa):
  │   ├─ -i wan -j ACCEPT
  │   └─ -o wan -j ACCEPT
  ├─> MAC Whitelist (si habilitada):
  │   ├─ -s AA:BB:CC:DD:EE:FF -j ACCEPT
  │   ├─ -s 11:22:33:44:55:66 -j ACCEPT
  │   └─ ...
  └─> DROP (final)

FORWARD_VLAN_2 (Otras VLANs)
  ├─> WAN rules (si PVLAN activa):
  │   ├─ -i wan -j ACCEPT
  │   └─ -o wan -j ACCEPT
  └─> DROP (solo si PVLAN activa)
```

### Lógica de Aplicación

**VLAN con PVLAN activa:**
1. Crear cadena `FORWARD_VLAN_X`
2. Redirigir tráfico de interfaces VLAN a cadena
3. Permitir tráfico WAN (`-i wan`, `-o wan`)
4. DROP resto del tráfico

**VLAN 1 con Whitelist:**
1. Crear cadena `FORWARD_VLAN_1`
2. Redirigir tráfico de interfaces VLAN 1
3. Si PVLAN: Agregar reglas WAN
4. Agregar reglas MAC whitelist
5. DROP resto del tráfico

**Compatibilidad:** PVLAN y Whitelist pueden estar activas simultáneamente en VLAN 1.

---

## Flujo de Trabajo Típico

### Configurar PVLAN

```bash
# 1. Verificar dependencias
wan status
vlans status
tagging status

# 2. Iniciar ebtables si no está activo
ebtables start

# 3. Aislar VLAN 2
ebtables aislar --vlan_id 2

# 4. Verificar
ebtables status
```

### Gestionar Whitelist VLAN 1

```bash
# 1. Agregar MACs de administradores
ebtables add_mac --mac 00:11:22:33:44:55
ebtables add_mac --mac AA:BB:CC:DD:EE:FF

# 2. Verificar configuración
ebtables show_whitelist

# 3. Habilitar si está deshabilitada
ebtables enable_whitelist

# 4. Para acceso temporal, deshabilitar
ebtables disable_whitelist

# 5. Volver a habilitar cuando termine
ebtables enable_whitelist
```

### Reiniciar con Nueva Configuración

```bash
# Eliminar configuración actual
ebtables stop

# Modificar VLANs si es necesario
vlans config --action add --id 3 --name Test --ip_interface 10.0.3.1/24 --ip_network 10.0.3.0/24

# Reiniciar ebtables (sincroniza con VLANs)
ebtables start

# La VLAN 1 se crea con whitelist habilitada por defecto
```

---

## Archivos de Configuración

### ebtables.json

Ubicación: `/opt/JSBach_V4.0/config/ebtables/ebtables.json`

```json
{
  "status": 1,
  "wan_interface": "eno1",
  "vlans": {
    "1": {
      "name": "Admin",
      "isolated": false,
      "mac_whitelist_enabled": true,
      "mac_whitelist": [
        "AA:BB:CC:DD:EE:FF",
        "11:22:33:44:55:66"
      ]
    },
    "2": {
      "name": "DMZ",
      "isolated": true
    }
  }
}
```

**Campos:**
- `status`: 0 = inactivo, 1 = activo
- `wan_interface`: Interfaz WAN detectada
- `vlans.<id>.isolated`: PVLAN activa (true) o inactiva (false)
- `vlans.1.mac_whitelist_enabled`: Whitelist habilitada
- `vlans.1.mac_whitelist`: Array de MACs autorizadas

---

## Troubleshooting

### Error: "Módulo inactivo"

**Causa:** Dependencias no activas o módulo detenido.

**Solución:**
```bash
# Verificar dependencias
wan status
vlans status
tagging status

# Iniciar las que falten
wan start
vlans start
tagging start

# Iniciar ebtables
ebtables start
```

### Error: "VLAN no configurada"

**Causa:** La VLAN no existe en vlans.json.

**Solución:**
```bash
# Ver VLANs disponibles
vlans status

# Configurar VLAN
vlans config --action add --id 2 --name Test --ip_interface 10.0.2.1/24 --ip_network 10.0.2.0/24
vlans start

# Reiniciar ebtables
ebtables restart
```

### Whitelist no Funciona

**Diagnóstico:**
```bash
# Ver estado
ebtables show_whitelist

# Verificar si está habilitada
ebtables status
```

**Soluciones:**
```bash
# Habilitar whitelist
ebtables enable_whitelist

# Verificar reglas (como root)
sudo ebtables -L FORWARD_VLAN_1 --Ln

# Reiniciar módulo
ebtables restart
```

### MAC No Se Agrega

**Causa:** Formato inválido o duplicado.

**Solución:**
```bash
# Usar formato correcto
ebtables add_mac --mac AA:BB:CC:DD:EE:FF

# Verificar si ya existe
ebtables show_whitelist

# Ver logs
sudo journalctl -u jsbach -f
```

---

## Comandos de Depuración

### Ver Reglas Ebtables (Como Root)

```bash
# Ver cadena FORWARD
sudo ebtables -L FORWARD --Ln

# Ver cadena específica de VLAN
sudo ebtables -L FORWARD_VLAN_1 --Ln
sudo ebtables -L FORWARD_VLAN_2 --Ln

# Ver todas las cadenas
sudo ebtables -L --Ln
```

### Ver Logs del Módulo

```bash
# Ver logs en tiempo real
sudo journalctl -u jsbach -f

# Filtrar por ebtables
sudo journalctl -u jsbach | grep -i ebtables

# Ver acciones recientes
cat /opt/JSBach_V4.0/logs/ebtables/actions.log
```

### Verificar Configuración

```bash
# Ver archivo de configuración
cat /opt/JSBach_V4.0/config/ebtables/ebtables.json | jq

# Verificar interfaces taggeadas
cat /opt/JSBach_V4.0/config/tagging/tagging.json | jq
```

---

## Notas Importantes

1. **VLAN 1 es Especial**: Es la única con whitelist de MAC
2. **Whitelist por Defecto**: En instalaciones nuevas, VLAN 1 tiene whitelist habilitada
3. **Compatibilidad**: PVLAN y MAC whitelist pueden coexistir en VLAN 1
4. **Persistencia**: Configuración guardada en JSON, se mantiene entre reinicios
5. **Formato MAC**: Se normaliza automáticamente (mayúsculas con dos puntos)
6. **Sincronización**: Al hacer `start` o `restart`, se sincroniza con VLANs activas
7. **Limpieza**: Al hacer `stop`, se eliminan todas las cadenas y reglas

---

## Integración con Otros Módulos

### Con Firewall
- **Firewall** opera en capa 3 (IP)
- **Ebtables** opera en capa 2 (MAC/Ethernet)
- Ambos pueden estar activos simultáneamente
- Ebtables se evalúa ANTES que firewall (más bajo nivel)

### Con VLANs/Tagging
- Ebtables se sincroniza automáticamente con cambios en VLANs
- Al agregar/eliminar VLANs, hacer `ebtables restart`
- Depende del mapeo de interfaces del módulo Tagging

### Con NAT/WAN
- Requiere saber la interfaz WAN para reglas de PVLAN
- NAT opera después de ebtables en el flujo de paquetes

---

**Ayuda del módulo EBTABLES - JSBach V4.0**
