function openPage(page, btn) {
    const iframe = parent.frames['body'];

    // Resaltar botón seleccionado
    document.querySelectorAll("button").forEach(b => b.classList.remove("selected"));
    btn.classList.add("selected");
    sessionStorage.setItem("dmzSelected", btn.id);

    iframe.location.href = `/web/dmz/${page}.html`;
}

function executeAction(action, btn) {
    const iframe = parent.frames['body'];

    // Resaltar botón seleccionado
    document.querySelectorAll("button").forEach(b => b.classList.remove("selected"));
    btn.classList.add("selected");
    sessionStorage.setItem("dmzSelected", btn.id);

    // START/STOP/RESTART/STATUS → cargar status.html para feedback
    if (action === 'start' || action === 'stop' || action === 'restart' || action === 'status') {
        iframe.location.href = "/web/dmz/status.html";
    } else {
        // Otras acciones → mostrar info.html
        iframe.location.href = "/web/dmz/info.html";
    }

    // Ejecutar acción en segundo plano
    // ...

    fetch('/admin/dmz', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ action: action })
    })
    .then(response => {
        // ...
        return response.json();
    })
    .then(data => {
        // ...
    })
    .catch(error => {
        console.error('DMZ: Error ejecutando acción:', error);
    });
}

// Restaurar el botón seleccionado al cargar la página
window.onload = function() {
    const selected = sessionStorage.getItem("dmzSelected");
    if (selected) {
        const btn = document.getElementById(selected);
        if (btn) btn.classList.add("selected");
    }
    fetchModuleStatus();
};

// Variables para polling adaptativo
let lastStatus = null;
let unchangedCount = 0;
let pollInterval = 2000;
let statusTimerId = null;

function fetchModuleStatus() {
    fetch('/admin/status', { credentials: 'include' })
    .then(response => response.json())
    .then(data => {
        const status = data['dmz'] || 'DESCONOCIDO';

        // Actualizar UI de estado con polling adaptativo
        if (status === lastStatus) {
            // Si no cambió, ralentizar gradualmente
            unchangedCount++;
            if (unchangedCount > 3) pollInterval = 5000;   // Después de 3 = 5s
            if (unchangedCount > 10) pollInterval = 10000; // Después de 10 = 10s
            if (unchangedCount > 20) pollInterval = 30000; // Después de 20 = 30s
        } else {
            // Si cambió, volver a polling rápido y actualizar UI
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

        // Re-programar con el nuevo intervalo
        clearTimeout(statusTimerId);
        statusTimerId = setTimeout(fetchModuleStatus, pollInterval);
    })
    .catch(error => {
        console.error('Error al obtener estado:', error);
        clearTimeout(statusTimerId);
        statusTimerId = setTimeout(fetchModuleStatus, 5000); // Retry en 5s
    });
}

async function checkDependencies() {
    // Verificar NAT
    const btnStart = document.getElementById('btnStart');
    try {
        const natResp = await fetch('/admin/nat/info', { credentials: 'include' });
        const natData = await natResp.json();
        const natDiv = document.getElementById('dep-nat');
        if (natData.status === 1) {
            natDiv.innerHTML = '✅ NAT: Activo';
            natDiv.style.color = '#155724';
            // Habilitar botón START
            btnStart.disabled = false;
            btnStart.title = '';
        } else {
            natDiv.innerHTML = '❌ NAT: Inactivo (Requerido)';
            natDiv.style.color = '#721c24';
            // Deshabilitar botón START
            btnStart.disabled = true;
            btnStart.title = 'NAT debe estar activo primero';
        }
    } catch {
        document.getElementById('dep-nat').innerHTML = '⚠️ NAT: Error al verificar';
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