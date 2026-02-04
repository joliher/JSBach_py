let firewallConfig = {};
let vlansConfig = {};

async function loadConfig() {
    try {
        // ...

        // Cargar configuración del firewall
        // ...
        const fwResponse = await fetch('/config/firewall/firewall.json', {
            credentials: 'include'
    });

    // ...

    if (!fwResponse.ok) {
        throw new Error('No se pudo cargar la configuración del firewall. Status: ' + fwResponse.status);
    }

    firewallConfig = await fwResponse.json();
    // ...

    // Cargar configuración de VLANs
    // ...
    const vlansResponse = await fetch('/config/vlans/vlans.json', {
        credentials: 'include'
    });

// ...

if (!vlansResponse.ok) {
    throw new Error('No se pudo cargar la configuración de VLANs. Status: ' + vlansResponse.status);
}

vlansConfig = await vlansResponse.json();
// ...
// ...
renderTable();

} catch (error) {
    console.error('Error cargando configuración:', error);
    document.getElementById('content').innerHTML = `
    <div class="warning-box">
    ⚠️ Error al cargar configuración. Asegúrese de que:
    <ul style="margin: 10px 0 0 20px;">
    <li>El firewall esté iniciado (START)</li>
    <li>Existan VLANs configuradas en el sistema</li>
    <li>Los archivos de configuración sean accesibles</li>
    </ul>
    </div>
    `;
}
}

function renderTable() {
    // ...
    const fwVlans = firewallConfig.vlans || {};
    const systemVlans = vlansConfig.vlans || [];

    // ...
    // ...
    // ...

    if (systemVlans.length === 0) {
        // ...
        document.getElementById('content').innerHTML = `
        <div class="empty-state">
        <div class="empty-state-icon">📭</div>
        <h3>No hay VLANs configuradas</h3>
        <p>Configure VLANs en el módulo correspondiente para verlas aquí.</p>
        </div>
        `;
        return;
    }

    // ...

    let html = `
    <table>
    <thead>
    <tr>
    <th>VLAN ID</th>
    <th>Nombre</th>
    <th>IP/Máscara</th>
    <th>Estado Firewall</th>
    </tr>
    </thead>
    <tbody>
    `;

    // Ordenar VLANs por ID
    systemVlans.sort((a, b) => a.id - b.id);

    systemVlans.forEach(vlan => {
        const vlanId = vlan.id;
        const vlanName = vlan.name || 'Sin nombre';
        const vlanIp = vlan.ip_network || 'N/A';

        // Información del firewall para esta VLAN
        const fwVlan = fwVlans[String(vlanId)] || {};
        const isActive = fwVlan.enabled || false;
        const isolated = fwVlan.isolated || false;
        const whitelistEnabled = fwVlan.whitelist_enabled || false;
        const whitelistRules = fwVlan.whitelist || [];
        const restricted = fwVlan.restricted || false;
        const ruleCount = whitelistRules.length;

        // Generar matriz de estado (más compacta y visual)
        const stateMatrix = `
        <div class="status-matrix">
        <div class="status-matrix-label">Cadena FW:</div>
        <div class="status-matrix-value ${isActive ? 'active' : 'inactive'}">
        ${isActive ? '✓ Activa' : '✗ Inactiva'}
        </div>
        <div class="status-matrix-label">Whitelist:</div>
        <div class="status-matrix-value ${vlanId == 1 || vlanId == 2 ? 'disabled' : (whitelistEnabled ? 'active' : 'inactive')}">
        ${vlanId == 1 || vlanId == 2 ? 'N/A' : (whitelistEnabled ? `✓ (${ruleCount})` : '✗')}
        </div>
        <div class="status-matrix-label">Aislada:</div>
        <div class="status-matrix-value ${isolated ? 'active' : 'inactive'}">
        ${isolated ? '✓ Sí' : '✗ No'}
        </div>
        <div class="status-matrix-label">Restricciones:</div>
        <div class="status-matrix-value ${restricted ? 'active' : 'inactive'}">
        ${restricted ? '✓ Activas' : '✗ No'}
        </div>
        </div>
        `;

        html += `
        <tr>
        <td style="font-weight: bold; text-align: center; width: 60px;">${vlanId}</td>
        <td style="width: 150px;">${vlanName}</td>
        <td><code>${vlanIp}</code></td>
        <td style="width: 400px;">
        ${stateMatrix}
        </td>
        </tr>
        `;
    });

// ...

html += `
</tbody>
</table>

<div class="info-box" style="margin-top: 30px;">
<strong>ℹ️ Información de Estados:</strong>
<ul style="margin: 10px 0 0 20px; line-height: 1.8;">
<li><strong>Cadena FW:</strong> Estado de la cadena de firewall para la VLAN.</li>
<li><strong>Whitelist:</strong> Modo whitelist habilitado (solo VLANs 3+). Número de reglas entre paréntesis.</li>
<li><strong>Aislada:</strong> Bloquea tráfico entre VLANs (FORWARD).</li>
<li><strong>Restricciones:</strong> Bloquea acceso al router (INPUT). Para VLANs 1-2: DROP total. Para otras: permite DHCP e ICMP.</li>
</ul>
</div>

<div class="info-box" style="margin-top: 20px;">
<strong>💡 Gestión de Firewall:</strong>
<ul style="margin: 10px 0 0 20px; line-height: 1.8;">
<li><strong>START/STOP:</strong> Usa el menú principal para activar/desactivar el firewall</li>
<li><strong>CONFIG WHITELIST:</strong> Configurar reglas de whitelist, aislar/desaislar y restringir/desrestringir</li>
<li><strong>STATUS:</strong> Ver estado detallado y reglas de iptables activas</li>
</ul>
</div>
`;

document.getElementById('content').innerHTML = html;
// ...
}

// Cargar configuración al iniciar
window.addEventListener('DOMContentLoaded', loadConfig);

// Recargar cada 10 segundos para mantener actualizado
setInterval(loadConfig, 10000);