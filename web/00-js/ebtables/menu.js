let statusCheckInterval;

function runEbtables(evt, action, btn) {
    evt.preventDefault();

    // Marcar botón seleccionado
    document.querySelectorAll('button').forEach(b => b.classList.remove('selected'));
    btn.classList.add('selected');

    const iframe = parent.frames['body'];
    if (action === "start" || action === "stop" || action === "restart" || action === "status") {
        iframe.location.href = "/web/ebtables/status.html";

        fetch('/admin/ebtables', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action: action }),
            credentials: 'include'
    }).catch(err => console.error('Error:', err));
}
}

function goConfig(evt, btn) {
    evt.preventDefault();
    document.querySelectorAll('button').forEach(b => b.classList.remove('selected'));
    btn.classList.add('selected');
    parent.frames['body'].location.href = "/web/ebtables/config.html";
}

function goInfo(evt, btn) {
    evt.preventDefault();
    document.querySelectorAll('button').forEach(b => b.classList.remove('selected'));
    btn.classList.add('selected');
    parent.frames['body'].location.href = "/web/ebtables/info.html";
}

async function checkModuleStatus() {
    try {
        const response = await fetch('/admin/ebtables/info', {
            credentials: 'include'
    });
    const data = await response.json();

    const statusBox = document.getElementById('module-status');
    if (data.status === 1) {
        statusBox.textContent = 'Estado: ACTIVO';
        statusBox.className = 'status-box activo';
    } else {
        statusBox.textContent = 'Estado: INACTIVO';
        statusBox.className = 'status-box inactivo';
    }
} catch (error) {
    document.getElementById('module-status').textContent = 'Estado: DESCONOCIDO';
    document.getElementById('module-status').className = 'status-box desconocido';
}
}

async function checkDependencies() {
    // Verificar WAN
    try {
        const wanResp = await fetch('/admin/wan/info', { credentials: 'include' });
        const wanData = await wanResp.json();
        const wanDiv = document.getElementById('dep-wan');
        if (wanData.status === 1) {
            wanDiv.innerHTML = '✅ WAN: Activo';
            wanDiv.style.color = '#155724';
        } else {
            wanDiv.innerHTML = '❌ WAN: Inactivo';
            wanDiv.style.color = '#721c24';
        }
    } catch {
        document.getElementById('dep-wan').innerHTML = '⚠️ WAN: Error al verificar';
    }

    // Verificar VLANs
    try {
        const vlansResp = await fetch('/admin/vlans/info', { credentials: 'include' });
        const vlansData = await vlansResp.json();
        const vlansDiv = document.getElementById('dep-vlans');
        if (vlansData.status === 1) {
            vlansDiv.innerHTML = '✅ VLANs: Activo';
            vlansDiv.style.color = '#155724';
        } else {
            vlansDiv.innerHTML = '❌ VLANs: Inactivo';
            vlansDiv.style.color = '#721c24';
        }
    } catch {
        document.getElementById('dep-vlans').innerHTML = '⚠️ VLANs: Error al verificar';
    }

    // Verificar Tagging
    try {
        const taggingResp = await fetch('/admin/tagging/info', { credentials: 'include' });
        const taggingData = await taggingResp.json();
        const taggingDiv = document.getElementById('dep-tagging');
        if (taggingData.status === 1) {
            taggingDiv.innerHTML = '✅ Tagging: Activo';
            taggingDiv.style.color = '#155724';
        } else {
            taggingDiv.innerHTML = '❌ Tagging: Inactivo';
            taggingDiv.style.color = '#721c24';
        }
    } catch {
        document.getElementById('dep-tagging').innerHTML = '⚠️ Tagging: Error al verificar';
    }
}

/* -----------------------------
Inicialización cuando el DOM está listo
----------------------------- */

document.addEventListener("DOMContentLoaded", function() {
    // Verificar estado inicial
    checkModuleStatus();
    checkDependencies();

    // Actualizar estado cada 5 segundos
    statusCheckInterval = setInterval(() => {
        checkModuleStatus();
        checkDependencies();
    }, 5000);

    // Limpiar intervalo al salir
    window.addEventListener('beforeunload', () => {
        if (statusCheckInterval) clearInterval(statusCheckInterval);
    });
});