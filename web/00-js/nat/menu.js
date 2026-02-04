function runNat(event, action, btn) {
    // 🔒 Evitar que el botón navegue el iframe izquierdo
    event.preventDefault();
    event.stopPropagation();

    const iframe = parent.frames['body'];
    if (!iframe) {
        console.error("Iframe 'body' no encontrado");
        return;
    }

    // Marcar botón seleccionado
    const botones = document.querySelectorAll("button");
    botones.forEach(b => b.classList.remove("selected"));
    btn.classList.add("selected");

    sessionStorage.setItem("natSelected", btn.id);

    // Acción CONFIG → cargar config.html en iframe derecho
    if (action === "config") {
        iframe.location.href = "/web/nat/config.html";
        return;
    }

    // Acciones START/STOP/RESTART/STATUS → cargar status.html para feedback
    if (action === "start" || action === "stop" || action === "restart" || action === "status") {
        iframe.location.href = "/web/nat/status.html";
        // Ejecutar acción backend
        fetch('/admin/nat', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action }),
            credentials: 'include'
    }).catch(error => {
        console.error("Error al ejecutar la acción:", error);
    });
return;
}

// Otras acciones → mostrar info.html
iframe.location.href = "/web/nat/info.html";
}

// Restaurar botón seleccionado
window.addEventListener("DOMContentLoaded", () => {
    const saved = sessionStorage.getItem("natSelected");
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
        const status = data['nat'] || 'DESCONOCIDO';

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

function openInfo(event, btn) {
    event.preventDefault();
    event.stopPropagation();

    const iframe = parent.frames['body'];
    if (!iframe) return;

    document.querySelectorAll("button").forEach(b => b.classList.remove("selected"));
    btn.classList.add("selected");
    sessionStorage.setItem("natSelected", btn.id);

    iframe.location.href = "/web/nat/info.html";
}

async function checkDependencies() {
    // Verificar WAN
    const btnStart = document.getElementById('btnStart');
    try {
        const wanResp = await fetch('/admin/wan/info', { credentials: 'include' });
        const wanData = await wanResp.json();
        const wanDiv = document.getElementById('dep-wan');
        if (wanData.status === 1) {
            wanDiv.innerHTML = '✅ WAN: Activo';
            wanDiv.style.color = '#155724';
            // Habilitar botón START
            btnStart.disabled = false;
            btnStart.title = '';
        } else {
            wanDiv.innerHTML = '❌ WAN: Inactivo (Requerido)';
            wanDiv.style.color = '#721c24';
            // Deshabilitar botón START
            btnStart.disabled = true;
            btnStart.title = 'WAN debe estar activo primero';
        }
    } catch {
        document.getElementById('dep-wan').innerHTML = '⚠️ WAN: Error al verificar';
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