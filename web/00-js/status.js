// Función para obtener el estado de los módulos
function fetchStatus() {
    fetch("/admin/status")
    .then(response => response.json())
    .then(data => {
        const tableBody = document.getElementById("status-table");
        tableBody.innerHTML = "";  // Limpiar tabla antes de llenarla

        // Orden de módulos por dependencias
        const moduleOrder = ["expect", "ebtables", "dmz", "firewall", "nat", "tagging", "vlans", "wan"];

        moduleOrder.forEach(module => {
            const status = data[module] || "DESCONOCIDO";
            let statusClass = "desconocido";
            let displayStatus = status;

            if (module === "expect") {
                statusClass = "fijo";
                displayStatus = "SIEMPRE ACTIVO";
            } else if (status === "ACTIVO") {
                statusClass = "activo";
            } else if (status === "INACTIVO") {
                statusClass = "inactivo";
            }

            const row = document.createElement("tr");
            row.innerHTML = `
            <td>${module.toUpperCase()}</td>
            <td class="status ${statusClass}">${displayStatus}</td>
            `;
            tableBody.appendChild(row);
        });
    })
    .catch(error => {
        console.error("Error al obtener el estado:", error);
        document.getElementById("status-table").innerHTML = `
        <tr>
            <td colspan="2" style="text-align: center; color: red;">Error al obtener el estado de los módulos.</td>
        </tr>
        `;
    });
}

async function stopAllModules() {
    const modules = ["ebtables", "firewall", "dmz", "nat", "tagging", "vlans", "wan"];
    const stopBtn = document.getElementById("stop-btn");
    const messageDiv = document.getElementById("stop-message");

    stopBtn.disabled = true;
    stopBtn.textContent = "⏳ Deteniendo módulos...";
    messageDiv.style.display = "none";

    let successCount = 0;
    let failedModules = [];

    for (const module of modules) {
        try {
            const response = await fetch(`/admin/${module}`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ action: "stop", params: null })
            });
            const result = await response.json();
            if (result.success) successCount++;
            else failedModules.push(module);
        } catch (error) {
            failedModules.push(module);
        }
    }

    messageDiv.style.display = "block";
    if (failedModules.length === 0) {
        messageDiv.className = "success-msg";
        messageDiv.textContent = `✅ Todos los módulos (${successCount}) han sido detenidos correctamente`;
    } else {
        messageDiv.className = "error-msg";
        messageDiv.textContent = `⚠️ ${successCount} módulos detenidos. Fallos en: ${failedModules.join(", ")}`;
    }

    setTimeout(() => { fetchStatus(); }, 1000);
    stopBtn.disabled = false;
    stopBtn.textContent = "🛑 Detener Todos los Módulos";
}

function fetchWanConfig() {
    fetch("/config/wan/wan.json")
    .then(response => response.json())
    .then(data => {
        const interfaceElement = document.getElementById("wan-interface");
        const modeElement = document.getElementById("wan-mode");
        const infoBox = document.getElementById("wan-interface-info");
        if (data.interface) {
            interfaceElement.textContent = data.interface;
            modeElement.textContent = data.mode ? "(" + data.mode.toUpperCase() + ")" : "";
            infoBox.style.display = "block";
        }
    })
    .catch(error => console.error("Error:", error));
}

window.onload = function() {
    fetchStatus();
    fetchWanConfig();
};
