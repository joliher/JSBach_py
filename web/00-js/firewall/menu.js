async function runAction(action, btn) {
    const iframe = parent.frames['body'];

    // Resaltar botón seleccionado
    document.querySelectorAll("button").forEach(b => b.classList.remove("selected"));
    btn.classList.add("selected");
    sessionStorage.setItem("firewallSelected", btn.id);

    // Para start/stop/restart/status, redirigir a status.html para feedback
    if (action === 'start' || action === 'stop' || action === 'restart' || action === 'status') {
        iframe.location.href = "/web/firewall/status.html";
        // Ejecutar acción en segundo plano
        // ...

        fetch('/admin/firewall', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action: action }),
            credentials: 'include'
        })
        .then(response => {
            // ...
            return response.json();
        })
        .then(data => {
            // ...
        })
        .catch(error => {
            console.error("Error al ejecutar la acción:", error);
    });
    return;
}

// Otras acciones
iframe.location.href = "/web/firewall/info.html";
}

function openConfig(section, btn) {
    const iframe = parent.frames['body'];

    // Resaltar botón seleccionado
    document.querySelectorAll("button").forEach(b => b.classList.remove("selected"));
    btn.classList.add("selected");
    sessionStorage.setItem("firewallSelected", btn.id);

    // Redirigir a la página correspondiente
    if (section === "vlans") {
        iframe.location.href = "/web/firewall/view_vlans.html";
    } else if (section === "whitelist") {
        iframe.location.href = "/web/firewall/config_whitelist.html";
    }
}

function openInfo(event, btn) {
    if (event) {
        event.preventDefault();
        event.stopPropagation();
    }

    const iframe = parent.frames['body'];
    if (!iframe) return;

    document.querySelectorAll("button").forEach(b => b.classList.remove("selected"));
    btn.classList.add("selected");
    sessionStorage.setItem("firewallSelected", btn.id);

    iframe.location.href = "/web/firewall/info.html";
}

function openLogs(btn) {
    const iframe = parent.frames['body'];

    // Resaltar botón seleccionado
    document.querySelectorAll("button").forEach(b => b.classList.remove("selected"));
    btn.classList.add("selected");
    sessionStorage.setItem("firewallSelected", btn.id);

    // Cargar logs
    iframe.location.href = "/web/firewall/logs.html";
}

// Mantener botón seleccionado al recargar
window.addEventListener("DOMContentLoaded", () => {
    const saved = sessionStorage.getItem("firewallSelected");
    if (saved) {
        const btn = document.getElementById(saved);
        if (btn) btn.classList.add("selected");
    }
    fetchModuleStatus();
});

// Función para obtener el estado del módulo con polling adaptativo
let lastStatus = '';
let pollInterval = 2000;
let unchangedCount = 0;
let statusTimerId = null;

function fetchModuleStatus() {
    fetch('/admin/status', { credentials: 'include' })
    .then(response => response.json())
    .then(data => {
        const status = data['firewall'] || 'DESCONOCIDO';

        if (status === lastStatus) {
            unchangedCount++;
            if (unchangedCount > 3) pollInterval = 5000;
            if (unchangedCount > 10) pollInterval = 10000;
            if (unchangedCount > 20) pollInterval = 30000;
        } else {
            lastStatus = status;
            unchangedCount = 0;
            pollInterval = 2000;

            const statusBox = document.getElementById('module-status');
            statusBox.textContent = `Estado: ${status}`;
            statusBox.classList.remove('activo', 'inactivo', 'desconocido');

            if (status === 'ACTIVO') {
                statusBox.classList.add('activo');
            } else if (status === 'INACTIVO') {
                statusBox.classList.add('inactivo');
            } else {
                statusBox.classList.add('desconocido');
            }
        }

        clearTimeout(statusTimerId);
        statusTimerId = setTimeout(fetchModuleStatus, pollInterval);
    })
    .catch(error => {
        console.error('Error al obtener estado:', error);
        clearTimeout(statusTimerId);
        statusTimerId = setTimeout(fetchModuleStatus, 5000);
    });
}

async function checkDependencies() {
    // Verificar VLANs
    const btnStart = document.getElementById('btnStart');
    try {
        const vlansResp = await fetch('/admin/vlans/info', { credentials: 'include' });
        const vlansData = await vlansResp.json();
        const vlansDiv = document.getElementById('dep-vlans');
        if (vlansData.status === 1) {
            vlansDiv.innerHTML = '✅ VLANs: Activo';
            vlansDiv.style.color = '#155724';
            // Habilitar botón START
            btnStart.disabled = false;
            btnStart.title = '';
        } else {
            vlansDiv.innerHTML = '❌ VLANs: Inactivo (Requerido)';
            vlansDiv.style.color = '#721c24';
            // Deshabilitar botón START
            btnStart.disabled = true;
            btnStart.title = 'VLANs debe estar activo primero';
        }
    } catch {
        document.getElementById('dep-vlans').innerHTML = '⚠️ VLANs: Error al verificar';
        // Deshabilitar botón START por error
        btnStart.disabled = true;
        btnStart.title = 'Error al verificar dependencias';
    }
}

// Verificar dependencias al cargar
window.addEventListener("DOMContentLoaded", () => {
    checkDependencies();
    // Actualizar dependencias cada 5 segundos
    setInterval(checkDependencies, 5000);
});