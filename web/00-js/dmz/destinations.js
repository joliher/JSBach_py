let currentStatus = null;

function showResult(message, isSuccess) {
    const resultDiv = document.getElementById('result');
    resultDiv.textContent = message;
    resultDiv.className = isSuccess ? 'success' : 'error';
    resultDiv.style.display = 'block';
    setTimeout(() => { resultDiv.style.display = 'none'; }, 5000);
}

async function loadStatus() {
    try {
        // Cargar configuración DMZ directamente desde el archivo JSON
        const dmzResponse = await fetch('/config/dmz/dmz.json', {
            credentials: 'include'
    });

    if (!dmzResponse.ok) {
        throw new Error('No se pudo cargar la configuración DMZ');
    }

    const dmzConfig = await dmzResponse.json();

    // Cargar configuración WAN para obtener la interfaz
    const wanResponse = await fetch('/config/wan/wan.json', {
        credentials: 'include'
    });

const wanConfig = wanResponse.ok ? await wanResponse.json() : null;

// Cargar configuración VLANs para verificar si están activas
const vlansResponse = await fetch('/config/vlans/vlans.json', {
    credentials: 'include'
});

const vlansConfig = vlansResponse.ok ? await vlansResponse.json() : null;

// Construir objeto de estado
currentStatus = {
    status: dmzConfig.status || 0,
    destinations: dmzConfig.destinations || [],
    wan_interface: wanConfig ? (wanConfig.interface || 'N/A') : 'N/A',
    vlans_active: vlansConfig ? (vlansConfig.status === 1) : false
};

renderStatus();
} catch (err) {
    console.error('Error en loadStatus:', err);
    showResult(`❌ Error cargando estado: ${err.message}`, false);

    // Mostrar mensaje en la tabla
    const tableContainer = document.getElementById('tableContainer');
    tableContainer.innerHTML = `
    <div class="warning-box">
    <strong>⚠️ Error al cargar configuración:</strong><br>
    ${err.message}<br><br>
    <em>Si es la primera vez que usas DMZ, ve a CONFIG para añadir un destino.</em>
    </div>
    `;
}
}

function renderStatus() {
    if (!currentStatus) return;

    const dmzStatusSpan = document.getElementById('dmzStatus');
    const isActive = currentStatus.status === 1;
    dmzStatusSpan.innerHTML = isActive
    ? '<span class="status-badge status-active">✅ ACTIVO</span>'
    : '<span class="status-badge status-inactive">❌ INACTIVO</span>';

    document.getElementById('wanInterface').textContent = currentStatus.wan_interface;

    const vlansActive = currentStatus.vlans_active;
    const vlansSpan = document.getElementById('vlansStatus');
    vlansSpan.innerHTML = vlansActive
    ? '<span class="status-badge status-active">✅ ACTIVAS</span>'
    : '<span class="status-badge status-inactive">❌ INACTIVAS</span>';

    document.getElementById('warningBox').style.display = vlansActive ? 'none' : 'block';

    renderTable();
}

function renderTable() {
    const tableContainer = document.getElementById('tableContainer');
    const destinations = currentStatus.destinations || [];

    if (destinations.length === 0) {
        tableContainer.innerHTML = '<p class="empty-message">No hay destinos DMZ configurados. Ve a CONFIG para añadir uno.</p>';
        return;
    }

    let tableHTML = `
    <table>
    <thead>
    <tr>
    <th>IP</th>
    <th>Puerto</th>
    <th>Protocolo</th>
    <th>Estado</th>
    <th>Acciones</th>
    </tr>
    </thead>
    <tbody>
    `;

    destinations.forEach(dest => {
        const isolated = dest.isolated || false;
        const dmzActive = currentStatus.status === 1;

        // Determinar el badge de estado correcto
        let statusBadge;
        if (isolated) {
            statusBadge = '<span class="isolated-badge">🔒 AISLADO</span>';
        } else if (dmzActive) {
            statusBadge = '<span class="normal-badge">✅ ACTIVO</span>';
        } else {
            statusBadge = '<span class="status-badge status-inactive">⏸️ CONFIGURADO</span>';
        }

        // Botones de aislamiento/desaislamiento
        const isolateBtn = isolated
        ? `<button class="action-btn btn-unisolate" onclick="toggleIsolation('${dest.ip}', false)">🔓 DESAISLAR</button>`
        : `<button class="action-btn btn-isolate" onclick="toggleIsolation('${dest.ip}', true)">🔒 AISLAR</button>`;

        tableHTML += `
        <tr>
        <td><code>${dest.ip}</code></td>
        <td>${dest.port}</td>
        <td>${dest.protocol.toUpperCase()}</td>
        <td>${statusBadge}</td>
        <td>
        ${isolateBtn}
        <button class="action-btn btn-delete" onclick="deleteDestination('${dest.ip}', ${dest.port}, '${dest.protocol}')">🗑️ ELIMINAR</button>
        </td>
        </tr>
        `;
    });

tableHTML += `</tbody></table>`;
tableContainer.innerHTML = tableHTML;
}

async function executeAction(action, params = {}) {
    try {
        const response = await fetch('/admin/dmz', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ action: action, params: params })
    });

    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || 'Error desconocido');

    showResult(data.success ? `✅ ${data.message}` : `❌ ${data.message}`, data.success);

    // Redirigir a logs después de START o STOP
    if (action === 'start' || action === 'stop') {
        setTimeout(() => {
            window.location.href = '/web/dmz/logs.html';
        }, 1500);
    } else {
        // Para otras acciones, recargar estado después de 1 segundo
        setTimeout(loadStatus, 1000);
    }
} catch (err) {
    showResult(`❌ ${err.message}`, false);
}
}

// Función para aislar/desaislar host DMZ individual
async function toggleIsolation(ip, shouldIsolate) {
    const action = shouldIsolate ? 'isolate_dmz_host' : 'unisolate_dmz_host';
    const actionText = shouldIsolate ? 'aislar' : 'desaislar';

    const confirmed = confirm(
        `¿Estás seguro de ${actionText} el host DMZ ${ip}?\n\n` +
        (shouldIsolate
        ? '⚠️ El host quedará completamente bloqueado:\n' +
        '   • RETURN en PREROUTING_PROTECTION (NAT - bloquea DNAT)\n' +
        '   • El port forwarding NO se aplicará (impide acceso desde WAN)\n' +
        '   • DROP en INPUT (filter - bloquea tráfico desde host al router)\n' +
        'Esta acción tiene PRIORIDAD MÁXIMA: ocurre ANTES de DNAT.'
        : 'ℹ️ Se eliminarán los bloqueos de PREROUTING_PROTECTION e INPUT.\n' +
        'El host volverá a estar accesible y el port forwarding funcionará.')
        );

        if (!confirmed) return;

        await executeAction(action, { ip });
    }

    async function deleteDestination(ip, port, protocol) {
        if (!confirm(`¿Eliminar destino ${ip}:${port}/${protocol}? Esta acción no se puede deshacer.`)) return;
        await executeAction('remove_destination', { ip, port, protocol });
    }

    document.getElementById('btnRefresh').addEventListener('click', () => { loadStatus(); });

    window.addEventListener('DOMContentLoaded', loadStatus);
    setInterval(loadStatus, 10000);