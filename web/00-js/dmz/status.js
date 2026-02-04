async function refreshStatus() {
    const container = document.getElementById('statusContainer');
    const btn = document.getElementById('btnRefresh');

    btn.disabled = true;
    container.innerHTML = '<div class="loading">Cargando estado de DMZ...</div>';

    try {
        const response = await fetch('/admin/dmz', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action: 'status' }),
            credentials: 'include'
    });

    if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
    }

    const data = await response.json();

    if (data.success) {
        container.innerHTML = `
        <div class="success">✅ Estado obtenido correctamente</div>
        <div class="status-content">${escapeHtml(data.message)}</div>
        `;
    } else {
        container.innerHTML = `
        <div class="error">❌ Error: ${escapeHtml(data.message || 'Error desconocido')}</div>
        `;
    }
} catch (error) {
    console.error('Error:', error);
    container.innerHTML = `
    <div class="error">❌ Error al obtener el estado: ${escapeHtml(error.message)}</div>
    `;
} finally {
    btn.disabled = false;
}
}

function goBack() {
    if (parent && parent.frames['body']) {
        parent.frames['body'].location.href = '/web/dmz/info.html';
    }
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Cargar estado al abrir la página
window.addEventListener('DOMContentLoaded', refreshStatus);