async function loadVlans() {
    const container = document.getElementById('vlanContainer');

    try {
        // Verificar primero si el módulo ebtables está activo
        const ebtablesInfoResponse = await fetch('/admin/ebtables/info', {
            credentials: 'include'
        });
        const ebtablesInfo = await ebtablesInfoResponse.json();

        if (ebtablesInfo.status !== 1) {
            container.innerHTML = `
            <div style="text-align: center; padding: 40px; color: #eb3349;">
            <div style="font-size: 48px; margin-bottom: 20px;">⚠️</div>
            <h2 style="color: #eb3349; margin-bottom: 10px;">Módulo EBTABLES Inactivo</h2>
            <p style="color: #666; font-size: 16px;">
            El módulo EBTABLES debe estar activo para configurar PVLAN (Private VLAN).
            </p>
            <p style="color: #666; font-size: 14px; margin-top: 20px;">
            Por favor, inicie el módulo desde el menú antes de continuar.
            </p>
            </div>
            `;
            return;
        }

        // Obtener configuración de VLANs
        const vlansResponse = await fetch('/config/vlans/vlans.json?t=' + Date.now(), {
            credentials: 'include',
            cache: 'no-cache'
        });
        const vlansData = await vlansResponse.json();

        // Obtener estado del ebtables
        const ebtablesResponse = await fetch('/config/ebtables/ebtables.json?t=' + Date.now(), {
            credentials: 'include',
            cache: 'no-cache'
        });
        const ebtablesData = await ebtablesResponse.json();

        if (!vlansData.vlans || vlansData.vlans.length === 0) {
            container.innerHTML = `
            <div style="text-align: center; padding: 30px; color: #666;">
            No hay VLANs configuradas.
            <br>Por favor, configure las VLANs primero en el módulo VLANs.
            </div>
            `;
            return;
        }

        // Crear mapa de estado de aislamiento y whitelist
        const isolationMap = {};
        const whitelistConfig = {};
        if (ebtablesData.vlans) {
            // ebtablesData.vlans es un objeto con vlan_id como clave
            Object.keys(ebtablesData.vlans).forEach(vlanId => {
                const vlanConfig = ebtablesData.vlans[vlanId];
                isolationMap[vlanId] = vlanConfig.isolated || false;
                if (vlanId === '1') {
                    whitelistConfig.enabled = vlanConfig.mac_whitelist_enabled !== false;
                    whitelistConfig.list = vlanConfig.mac_whitelist || [];
                }
            });
        }

        // Ordenar VLANs por ID
        const sortedVlans = [...vlansData.vlans].sort((a, b) => a.id - b.id);

        // Generar HTML para cada VLAN
        let html = '<div class="vlan-list">';
        sortedVlans.forEach(vlan => {
            const isIsolated = isolationMap[vlan.id] || false;
            const isVlan1 = vlan.id === 1;
            
            html += `
            <div class="vlan-item" style="${isVlan1 ? 'border-left: 4px solid #667eea;' : ''}">
            <div class="vlan-item-header">
            <div class="vlan-info">
            <div class="vlan-id">VLAN ${vlan.id}${isVlan1 ? ' (Admin)' : ''}</div>
            <div class="vlan-status ${isIsolated ? 'isolated' : 'not-isolated'}">
            ${isIsolated ? '🔒 PVLAN ACTIVA' : '🔓 PVLAN INACTIVA'}
            </div>
            </div>
            <div class="btn-group">
            <button class="btn btn-isolate" id="btn-isolate-${vlan.id}"
            onclick="isolateVlan(${vlan.id})"
            ${isIsolated ? 'disabled' : ''}>
            🔒 Activar PVLAN
            </button>
            <button class="btn btn-unisolate" id="btn-unisolate-${vlan.id}"
            onclick="unisolateVlan(${vlan.id})"
            ${!isIsolated ? 'disabled' : ''}>
            🔓 Desactivar PVLAN
            </button>
            </div>
            </div>
            `;
            
            // Si es VLAN 1, agregar sección de whitelist
            if (isVlan1) {
                const whitelistEnabled = whitelistConfig.enabled;
                const whitelist = whitelistConfig.list;
                
                html += `
                <div class="mac-whitelist-section" style="margin-top: 15px; padding-top: 15px; border-top: 2px dashed #ddd;">
                <h4 style="margin-top: 0; color: #667eea;">🔐 Whitelist de MAC</h4>
                
                <div class="whitelist-status ${!whitelistEnabled ? 'disabled' : ''}">
                <span class="status-indicator"></span>
                <p>${whitelistEnabled ? '✅ Whitelist HABILITADA' : '⚠️ Whitelist DESHABILITADA'}</p>
                </div>
                
                ${!whitelistEnabled ? '<div class="alert alert-warning" style="margin: 10px 0;">⚠️ La whitelist está deshabilitada. Puedes agregar MACs pero no se aplicarán hasta que la habilites.</div>' : ''}
                
                <div class="whitelist-controls">
                <div class="mac-input-group">
                <input type="text" id="macInput" placeholder="Ej: AA:BB:CC:DD:EE:FF">
                <button class="btn btn-success btn-sm" id="btn-add-mac" onclick="addMac()">
                ➕ Agregar
                </button>
                </div>
                <button class="btn btn-secondary btn-sm" id="btn-toggle-whitelist" onclick="toggleWhitelist()">
                ${whitelistEnabled ? '🔒 Deshabilitar' : '🔓 Habilitar'}
                </button>
                </div>
                
                <h5 style="margin-top: 15px; margin-bottom: 8px; color: #555;">MACs en la Whitelist (${whitelist.length})</h5>
                <div class="mac-list">
                ${whitelist.length === 0 ?
                    '<div class="mac-list-empty">Sin MACs configuradas</div>' :
                    whitelist.map(mac => `
                    <div class="mac-item">
                    <span class="mac-addr">${escapeHtml(mac)}</span>
                    <button class="btn btn-danger btn-sm" onclick="removeMac('${escapeHtml(mac)}')">
                    ❌ Remover
                    </button>
                    </div>
                    `).join('')
                }
                </div>
                </div>
                `;
            }
            
            html += `</div>`;
        });
        html += '</div>';

        container.innerHTML = html;

    } catch (error) {
        container.innerHTML = `
        <div style="text-align: center; padding: 30px; color: #eb3349;">
        ❌ Error al cargar las VLANs: ${escapeHtml(error.message)}
        </div>
        `;
    }
}

async function loadMacWhitelist() {
    // Esta función ya no es necesaria porque la whitelist se carga con loadVlans()
    // Mantenerla vacía por compatibilidad
    return;
}

async function addMac() {
    const macInput = document.getElementById('macInput');
    const addButton = document.getElementById('btn-add-mac');
    let mac = macInput.value.trim();

    if (!mac) {
        showMessage('Error: Ingrese una dirección MAC', 'danger');
        return;
    }

    // Sanitizar entrada: eliminar espacios y caracteres peligrosos
    mac = mac.replace(/[^0-9A-Fa-f:-]/g, '');

    // Validar formato correcto
    if (!/^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/.test(mac)) {
        showMessage('Error: Formato de MAC inválido. Use: XX:XX:XX:XX:XX:XX o XX-XX-XX-XX-XX-XX', 'danger');
        return;
    }

    // Deshabilitar botón y cambiar texto
    if (addButton) {
        addButton.disabled = true;
        addButton.innerHTML = '⏳ Agregando...';
    }

    await executeConfigAction('add_mac', { mac: mac }, 'Agregando MAC');
    macInput.value = '';
}

async function removeMac(mac) {
    // Validar formato de MAC antes de remover
    if (!/^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/.test(mac)) {
        showMessage('Error: Formato de MAC inválido', 'danger');
        return;
    }
    
    if (!confirm(`¿Remover MAC ${mac} de la whitelist?`)) {
        return;
    }

    await executeConfigAction('remove_mac', { mac: mac }, 'Removiendo MAC');
}

async function toggleWhitelist() {
    const toggleButton = document.getElementById('btn-toggle-whitelist');
    
    // Obtener estado actual con cache-busting
    const ebtablesResponse = await fetch('/config/ebtables/ebtables.json?t=' + Date.now(), {
        credentials: 'include',
        cache: 'no-cache'
    });
    const ebtablesData = await ebtablesResponse.json();
    const vlan1Config = ebtablesData.vlans?.['1'] || { mac_whitelist_enabled: false };
    const isEnabled = vlan1Config.mac_whitelist_enabled === true;

    const action = isEnabled ? 'disable_whitelist' : 'enable_whitelist';
    const actionText = isEnabled ? 'Desactivando whitelist' : 'Activando whitelist';
    
    // Deshabilitar botón y cambiar texto
    if (toggleButton) {
        toggleButton.disabled = true;
        toggleButton.innerHTML = '⏳ ' + actionText + '...';
    }
    
    await executeConfigAction(action, {}, actionText);
}

async function executeConfigAction(action, params, customActionText = null) {
    const messageContainer = document.getElementById('messageContainer');
    const displayAction = customActionText || action;
    
    messageContainer.innerHTML = `
    <div class="alert alert-info">
    ⏳ ${displayAction}...
    </div>
    `;

    try {
        // Usar las funciones principales directamente (add_mac, remove_mac, enable_whitelist, disable_whitelist)
        const response = await fetch('/admin/ebtables', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                action: action,
                params: params
            }),
            credentials: 'include'
        });

        const data = await response.json();

        if (data.success) {
            messageContainer.innerHTML = `
            <div class="alert alert-success">
            ${escapeHtml(data.message)}
            </div>
            `;
            // Recargar lista completa (incluye VLANs y whitelist)
            setTimeout(loadVlans, 1200);
        } else {
            messageContainer.innerHTML = `
            <div class="alert alert-danger">
            ❌ ${escapeHtml(data.message)}
            </div>
            `;
        }

        // Limpiar mensaje después de 5 segundos
        setTimeout(() => {
            messageContainer.innerHTML = '';
        }, 5000);

    } catch (error) {
        messageContainer.innerHTML = `
        <div class="alert alert-danger">
        ❌ Error: ${escapeHtml(error.message)}
        </div>
        `;
    }
}

async function isolateVlan(vlanId) {
    if (!confirm(`¿Confirma que desea ACTIVAR PVLAN en la VLAN ${vlanId}?\n\nSolo podrá comunicarse con la WAN.`)) {
        return;
    }

    // Deshabilitar botones
    const isolateBtn = document.getElementById(`btn-isolate-${vlanId}`);
    const unisolateBtn = document.getElementById(`btn-unisolate-${vlanId}`);
    
    if (isolateBtn) {
        isolateBtn.disabled = true;
        isolateBtn.innerHTML = '⏳ Activando PVLAN...';
    }
    if (unisolateBtn) {
        unisolateBtn.disabled = true;
    }

    await executeAction('aislar', vlanId);
}

async function unisolateVlan(vlanId) {
    if (!confirm(`¿Confirma que desea DESACTIVAR PVLAN en la VLAN ${vlanId}?`)) {
        return;
    }

    // Deshabilitar botones
    const isolateBtn = document.getElementById(`btn-isolate-${vlanId}`);
    const unisolateBtn = document.getElementById(`btn-unisolate-${vlanId}`);
    
    if (isolateBtn) {
        isolateBtn.disabled = true;
    }
    if (unisolateBtn) {
        unisolateBtn.disabled = true;
        unisolateBtn.innerHTML = '⏳ Desactivando PVLAN...';
    }

    await executeAction('desaislar', vlanId);
}

async function executeAction(action, vlanId) {
    const messageContainer = document.getElementById('messageContainer');
    messageContainer.innerHTML = `
    <div class="alert alert-info">
    ⏳ Procesando acción ${action} para VLAN ${vlanId}...
    </div>
    `;

    try {
        const response = await fetch('/admin/ebtables', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                action: action,
                params: {
                    vlan_id: vlanId.toString()
                }
            }),
            credentials: 'include'
        });

        const data = await response.json();

        if (data.success) {
            messageContainer.innerHTML = `
            <div class="alert alert-success">
            ${escapeHtml(data.message)}
            </div>
            `;
            // Recargar lista
            setTimeout(loadVlans, 1000);
        } else {
            messageContainer.innerHTML = `
            <div class="alert alert-danger">
            ❌ ${escapeHtml(data.message)}
            </div>
            `;
        }

        // Limpiar mensaje después de 5 segundos
        setTimeout(() => {
            messageContainer.innerHTML = '';
        }, 5000);

    } catch (error) {
        messageContainer.innerHTML = `
        <div class="alert alert-danger">
        ❌ Error al ejecutar acción: ${escapeHtml(error.message)}
        </div>
        `;
    }
}

function showMessage(message, type = 'info') {
    const messageContainer = document.getElementById('messageContainer');
    const alertClass = `alert alert-${type}`;
    const icon = type === 'success' ? '✅' : (type === 'danger' ? '❌' : 'ℹ️');
    messageContainer.innerHTML = `<div class="${alertClass}">${icon} ${escapeHtml(message)}</div>`;
    setTimeout(() => {
        messageContainer.innerHTML = '';
    }, 5000);
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Cargar al iniciar
window.addEventListener('DOMContentLoaded', () => {
    loadVlans();
});
