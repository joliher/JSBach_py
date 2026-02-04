let vlanCache = {};

function isValidCIDR(ip) {
    const parts = ip.split('/');
    if (parts.length !== 2) return false;
    const ipAddr = parts[0];
    const mask = parseInt(parts[1]);
    if (isNaN(mask) || mask < 1 || mask > 32) return false;
    const ipParts = ipAddr.split('.');
    if (ipParts.length !== 4) return false;
    for (let part of ipParts) {
        const num = parseInt(part);
        if (isNaN(num) || num < 0 || num > 255) return false;
    }
    return true;
}

function isValidNetworkIP(ip) {
    if (!isValidCIDR(ip)) return false;
    const ipParts = ip.split('/')[0].split('.');
    const lastOctet = parseInt(ipParts[3]);
    return lastOctet === 0;
}

function isValidInterfaceIP(ip) {
    if (!isValidCIDR(ip)) return false;
    const ipParts = ip.split('/')[0].split('.');
    const lastOctet = parseInt(ipParts[3]);
    return lastOctet !== 0 && lastOctet !== 255;
}

function isIpInNetwork(ipInterface, ipNetwork) {
    try {
        const ipParts = ipInterface.split('/')[0].split('.').map(p => parseInt(p));
        const netParts = ipNetwork.split('/')[0].split('.').map(p => parseInt(p));
        const mask = parseInt(ipNetwork.split('/')[1]);

        // Convertir IP e IP de red a números de 32 bits
        const ipNum = (ipParts[0] << 24) | (ipParts[1] << 16) | (ipParts[2] << 8) | ipParts[3];
        const netNum = (netParts[0] << 24) | (netParts[1] << 16) | (netParts[2] << 8) | netParts[3];

        // Crear máscara de red
        const maskNum = (0xFFFFFFFF << (32 - mask)) >>> 0;

        // Verificar si la IP está en la red
        return (ipNum & maskNum) === (netNum & maskNum);
    } catch (e) {
        return false;
    }
}

function haveSameMask(ipInterface, ipNetwork) {
    try {
        const mask1 = parseInt(ipInterface.split('/')[1]);
        const mask2 = parseInt(ipNetwork.split('/')[1]);
        return mask1 === mask2;
    } catch (e) {
        return false;
    }
}

async function loadVlans() {
    try {
        const response = await fetch("/admin/vlans", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            credentials: "include",
            body: JSON.stringify({
                action: "config",
                params: { action: "show" }
            })
    });

    const data = await response.json();

    if (!response.ok) {
        document.getElementById("output").textContent = data.detail || "Error cargando VLANs";
        return;
    }

    // Parsear VLANs del mensaje
    const vlans = [];
    const lines = data.message.split('\n');
    for (let line of lines) {
        const match = line.match(/ID:\s*(\d+),\s*Name:\s*([^,]+),\s*IP Interfaz:\s*([^,]+),\s*IP Red:\s*(.+)/);
        if (match) {
            vlans.push({
                id: parseInt(match[1]),
                name: match[2].trim(),
                ip_interface: match[3].trim(),
                ip_network: match[4].trim()
        });
    }
}

const tbody = document.querySelector("#vlansTable tbody");
tbody.innerHTML = "";
vlanCache = {};

// Ordenar por ID
vlans.sort((a, b) => a.id - b.id);

vlans.forEach(vlan => {
    vlanCache[vlan.id] = vlan;

    const tr = document.createElement("tr");
    tr.dataset.id = vlan.id;

    const isProtected = (vlan.id === 1 || vlan.id === 2);

    tr.innerHTML = `
    <td>${vlan.id}</td>
    <td>${vlan.name || ""}</td>
    <td>${vlan.ip_interface || ""}</td>
    <td>${vlan.ip_network || ""}</td>
    <td>
    <button class="btn-edit" onclick="editRow(${vlan.id})">Modificar</button>
    <button class="btn-delete" onclick="deleteVlan(${vlan.id})" ${isProtected ? 'disabled' : ''}>Eliminar</button>
    </td>
    `;

        tbody.appendChild(tr);
    });

    const outputDiv = document.getElementById("output");
    if (outputDiv) outputDiv.textContent = "";

    } catch (err) {
        const outputDiv = document.getElementById("output");
        if (outputDiv) outputDiv.textContent = "Error: " + err.message;
    }
}

function editRow(id) {
    const tr = document.querySelector(`tr[data-id="${id}"]`);
    const vlan = vlanCache[id];

    tr.innerHTML = `
    <td>${vlan.id}</td>
    <td><input type="text" value="${vlan.name || ""}"></td>
    <td><input type="text" value="${vlan.ip_interface || ""}"></td>
    <td><input type="text" value="${vlan.ip_network || ""}"></td>
    <td>
    <button class="btn-save" onclick="saveRow(${id})">Guardar</button>
    <button class="btn-cancel" onclick="cancelEdit()">Cancelar</button>
    </td>
    `;
}

async function saveRow(id) {
    const tr = document.querySelector(`tr[data-id="${id}"]`);
    const inputs = tr.querySelectorAll("input");
    const [name, ip_interface, ip_network] = Array.from(inputs).map(i => i.value.trim());
    const output = document.getElementById("output");

    // Validar nombre
    if (!name) {
        output.textContent = "❌ Error: Nombre no puede estar vacío";
        return;
    }

    // Validar IP de interfaz
    if (!ip_interface) {
        output.textContent = "❌ Error: IP de interfaz no puede estar vacía";
        return;
    }

    if (!isValidCIDR(ip_interface)) {
        output.textContent = "❌ Error: Formato de IP de interfaz inválido. Esperado: 192.168.1.1/24 (incluir máscara CIDR)";
        return;
    }

    if (!isValidInterfaceIP(ip_interface)) {
        output.textContent = "❌ Error: IP de interfaz no puede terminar en 0 (dirección de red) ni en 255 (broadcast). Use una IP de host válida (ej: 192.168.1.1).";
        return;
    }

    // Validar IP de red
    if (!ip_network) {
        output.textContent = "❌ Error: IP de red no puede estar vacía";
        return;
    }

    if (!isValidNetworkIP(ip_network)) {
        output.textContent = "❌ Error: IP de red debe terminar en 0 (ej: 192.168.1.0/24). Formato esperado: X.X.X.0/máscara";
        return;
    }

    if (!haveSameMask(ip_interface, ip_network)) {
        const maskIface = ip_interface.split('/')[1];
        const maskNet = ip_network.split('/')[1];
        output.textContent = `❌ Error: Las máscaras no coinciden. IP interfaz: /${maskIface}, IP red: /${maskNet}. Deben ser iguales.`;
        return;
    }

    if (!isIpInNetwork(ip_interface, ip_network)) {
        const ipAddr = ip_interface.split('/')[0];
        output.textContent = `❌ Error: La IP de interfaz ${ipAddr} no pertenece a la red ${ip_network}. Rango válido: desde ${ip_network.split('/')[0].replace(/0$/, '1')} hasta ${ip_network.split('/')[0].replace(/0$/, '254')}`;
        return;
    }

    try {
        const response = await fetch("/admin/vlans", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            credentials: "include",
            body: JSON.stringify({
                action: "config",
                params: {
                    action: "add",
                    id: id,
                    name: name,
                    ip_interface: ip_interface,
                    ip_network: ip_network
                }
            })
    });

    const data = await response.json();

    if (!response.ok) {
        output.textContent = "❌ " + (data.detail || data.message || "Error desconocido");
        return;
    }

    output.textContent = "✅ " + (data.message || "VLAN guardada exitosamente");
    loadVlans();

} catch (err) {
    document.getElementById("output").textContent = "Error: " + err.message;
}
}

function cancelEdit() {
    loadVlans();
}

async function deleteVlan(id) {
    if (!confirm(`¿Eliminar VLAN ${id}?`)) return;

    try {
        const response = await fetch("/admin/vlans", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            credentials: "include",
            body: JSON.stringify({
                action: "config",
                params: {
                    action: "remove",
                    id: id
                }
            })
    });

        const data = await response.json();
        document.getElementById("output").textContent = data.message || data.detail;
        loadVlans();

    } catch (err) {
        document.getElementById("output").textContent = "Error: " + err.message;
    }
}

/* -----------------------------
Inicialización cuando el DOM está listo
----------------------------- */

document.addEventListener("DOMContentLoaded", function() {
    const vlanForm = document.getElementById("vlanForm");
    
    vlanForm.addEventListener("submit", async (e) => {
        e.preventDefault();

    const form = e.target;
    const vlanId = form.id.value.trim();
    const name = form.name.value.trim();
    const ip_interface = form.ip_interface.value.trim();
    const ip_network = form.ip_network.value.trim();
    const output = document.getElementById("output");

    // Validar ID
    if (!vlanId) {
        output.textContent = "❌ Error: ID de VLAN no puede estar vacío";
        return;
    }

    const vlanIdNum = parseInt(vlanId);
    if (isNaN(vlanIdNum) || vlanIdNum < 1 || vlanIdNum > 4094) {
        output.textContent = "❌ Error: ID de VLAN debe estar entre 1 y 4094";
        return;
    }

    if (vlanIdNum === 1 || vlanIdNum === 2) {
        output.textContent = "❌ Error: VLANs 1 y 2 están protegidas y preconfiguradas";
        return;
    }

    // Validar nombre
    if (!name) {
        output.textContent = "❌ Error: Nombre no puede estar vacío";
        return;
    }

    // Validar IP de interfaz
    if (!ip_interface) {
        output.textContent = "❌ Error: IP de interfaz no puede estar vacía";
        return;
    }

    if (!isValidCIDR(ip_interface)) {
        output.textContent = "❌ Error: Formato de IP de interfaz inválido. Esperado: 192.168.1.1/24 (incluir máscara CIDR)";
        return;
    }

    if (!isValidInterfaceIP(ip_interface)) {
        output.textContent = "❌ Error: IP de interfaz no puede terminar en 0 (dirección de red) ni en 255 (broadcast). Use una IP de host válida (ej: 192.168.1.1).";
        return;
    }

    // Validar IP de red
    if (!ip_network) {
        output.textContent = "❌ Error: IP de red no puede estar vacía";
        return;
    }

    if (!isValidNetworkIP(ip_network)) {
        output.textContent = "❌ Error: IP de red debe terminar en 0 (ej: 192.168.1.0/24). Formato esperado: X.X.X.0/máscara";
        return;
    }

    if (!haveSameMask(ip_interface, ip_network)) {
        const maskIface = ip_interface.split('/')[1];
        const maskNet = ip_network.split('/')[1];
        output.textContent = `❌ Error: Las máscaras no coinciden. IP interfaz: /${maskIface}, IP red: /${maskNet}. Deben ser iguales.`;
        return;
    }

    if (!isIpInNetwork(ip_interface, ip_network)) {
        const ipAddr = ip_interface.split('/')[0];
        output.textContent = `❌ Error: La IP de interfaz ${ipAddr} no pertenece a la red ${ip_network}. Rango válido: desde ${ip_network.split('/')[0].replace(/0$/, '1')} hasta ${ip_network.split('/')[0].replace(/0$/, '254')}`;
        return;
    }

    try {
        const response = await fetch("/admin/vlans", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            credentials: "include",
            body: JSON.stringify({
                action: "config",
                params: {
                    action: "add",
                    id: parseInt(form.id.value),
                    name: form.name.value,
                    ip_interface: ip_interface,
                    ip_network: ip_network
                }
            })
    });

    const data = await response.json();

    if (!response.ok) {
        output.textContent = "❌ " + (data.detail || data.message || "Error desconocido");
    } else {
        output.textContent = "✅ " + (data.message || "VLAN guardada exitosamente");
    }

    form.reset();
        loadVlans();

    } catch (err) {
        document.getElementById("output").textContent = "❌ Error: " + err.message;
    }
    });

    // Cargar VLANs iniciales
    loadVlans();
});