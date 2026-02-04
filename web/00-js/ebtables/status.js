async function refreshStatus() {
    const container = document.getElementById('statusContainer');
    container.innerHTML = '<div class="loading">⏳ Consultando estado...</div>';

    try {
        const response = await fetch('/admin/ebtables', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action: 'status' }),
            credentials: 'include'
    });

    const data = await response.json();

    const statusIcon = data.success ? '✅' : '❌';
    const statusClass = data.success ? 'success' : 'error';

    container.innerHTML = `
    <div class="status-box">
    <div class="status-header">
    <span class="${statusClass}">${statusIcon}</span>
    Estado del Sistema Ebtables
    </div>
    <div class="status-content">${escapeHtml(data.message || 'Sin información disponible')}</div>
    </div>
    `;

} catch (error) {
    container.innerHTML = `
    <div class="status-box">
    <div class="status-header">
    <span class="error">❌</span> Error de Conexión
    </div>
    <div class="status-content">
    No se pudo conectar con el servidor.
    Error: ${escapeHtml(error.message)}
    </div>
    </div>
    `;
}
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Cargar estado automáticamente al abrir la página
window.addEventListener('DOMContentLoaded', refreshStatus);