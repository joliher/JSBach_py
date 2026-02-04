let taggingCache = {};
let vlanCache = {};
let ebtablesCache = {};

// ============ FUNCIONES DE VALIDACIÓN ============

function isValidInterfaceName(name) {
    return /^[a-zA-Z0-9._-]+$/.test(name);
}

function isValidVLANId(id) {
    const num = parseInt(id);
    return !isNaN(num) && num >= 1 && num <= 4094;
}

function validateVLANList(vlanList) {
    if (!vlanList) return { valid: true, errors: [] };

    const errors = [];

    if (/ /.test(vlanList)) {
        errors.push('No se permiten espacios. Formato válido: "1,2,3-10,12,14-15"');
        return { valid: false, errors };
    }

    const parts = vlanList.split(',');

    parts.forEach(part => {
        if (!part) {
            errors.push('No se permiten comas consecutivas');
            return;
        }

        if (part.includes('-')) {
            const rangeParts = part.split('-');
            if (rangeParts.length !== 2) {
                errors.push(`Rango inválido: "${part}"`);
                return;
            }
            const start = parseInt(rangeParts[0]);
            const end = parseInt(rangeParts[1]);
            if (isNaN(start) || isNaN(end) || start < 1 || start > 4094 || end < 1 || end > 4094) {
                errors.push(`Rango inválido: "${part}" (1-4094)`);
            }
        } else {
            if (!isValidVLANId(part)) {
                errors.push(`${part} no es un ID de VLAN válido (1-4094)`);
            }
        }
    });

return { valid: errors.length === 0, errors };
}

function validateAtLeastOneVLAN(vlan_untag, vlan_tag) {
    if (!vlan_untag && !vlan_tag) {
        return { valid: false, error: "Debe configurar al menos VLAN Untag o VLAN Tag" };
    }
    return { valid: true };
}

function validateNoUNTAGandTAG(vlan_untag, vlan_tag) {
    if (vlan_untag && vlan_tag) {
        return {
            valid: false,
            error: `Conflicto VLAN: No se puede estar UNTAGGED en VLAN ${vlan_untag} Y TAGGED en VLANs ${vlan_tag}. Seleccione UNO:\n• UNTAG: Acceso a solo una VLAN\n• TAG: Troncal con múltiples VLANs`
        };
    }
    return { valid: true };
}

function isValidVLANExists(vlanId) {
    return vlanCache && vlanCache[vlanId];
}

function isInterfaceUsedByEbtables(interfaceName) {
    // Seguro contra cache no inicializado
    if (!ebtablesCache || Object.keys(ebtablesCache).length === 0) {
        return { used: false };
    }

    for (let vlanId in ebtablesCache) {
        const vlan = ebtablesCache[vlanId];
        if (vlan && vlan.interfaces && Array.isArray(vlan.interfaces)) {
            if (vlan.interfaces.includes(interfaceName)) {
                return { used: true, vlanId: vlanId };
            }
        }
    }
    return { used: false };
}

async function loadAllData() {
    try {
        const tagResponse = await fetch("/admin/tagging", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            credentials: "include",
            body: JSON.stringify({ action: "config", params: { action: "show" } })
    });

    if (tagResponse.ok) {
        const tagData = await tagResponse.json();
        taggingCache = tagData.interfaces || {};
    }

    const vlanResponse = await fetch("/admin/vlans", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ action: "config", params: { action: "show" } })
    });

if (vlanResponse.ok) {
    const vlanData = await vlanResponse.json();
    vlanCache = {};
    if (vlanData.vlans && Array.isArray(vlanData.vlans)) {
        vlanData.vlans.forEach(v => { vlanCache[v.vlan_id] = v; });
    }
}

const ebtResponse = await fetch("/admin/ebtables", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    body: JSON.stringify({ action: "config", params: { action: "show" } })
});

if (ebtResponse.ok) {
    const ebtData = await ebtResponse.json();
    ebtablesCache = ebtData.vlans || {};
}

loadTagging();

} catch (err) {
    document.getElementById("output").textContent = "❌ Error cargando datos: " + err.message;
}
}

function showMessage(message) {
    const notification = document.getElementById("notification");
    notification.innerHTML = message.replace(/\n/g, "<br>");

    // Detectar tipo de mensaje
    let type = "info";
    if (message.startsWith("✅")) {
        type = "success";
    } else if (message.startsWith("❌")) {
        type = "error";
    } else if (message.startsWith("⚠️")) {
        type = "warning";
    }

    notification.className = `show ${type}`;

    // Auto-ocultar después de 6 segundos
    setTimeout(() => {
        notification.classList.remove("show");
    }, 6000);
}

async function loadTagging() {
    try {
        const response = await fetch("/admin/tagging", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            credentials: "include",
            body: JSON.stringify({ action: "config", params: { action: "show" } })
    });

    const data = await response.json();
    const tbody = document.querySelector("tbody");
    tbody.innerHTML = "";

    // Parsear el mensaje de texto del backend
    let interfaces = [];

    // Si la respuesta contiene un JSON con interfaces (array o objeto)
    if (typeof data.message === 'object') {
        interfaces = Array.isArray(data.message) ? data.message : Object.values(data.message || {});
    } else if (typeof data.message === 'string') {
        // Parsear el mensaje de texto de forma robusta
        const lines = data.message.split('\n');
        for (const line of lines) {
            const trimmedLine = line.trim();
            if (!trimmedLine) continue;

            // Intenta múltiples patrones
            const patterns = [
                /Name:\s*([^,]+),\s*UNTAG:\s*([^,]*),\s*TAG:\s*(.*)/i,
                /([^,]+?)\s+(?:UNTAG|untag):\s*([^,]*)\s+(?:TAG|tag):\s*(.*)/,
                /name[:\s]+([^,]+)[,\s]+(?:untag|vlan_untag)[:\s]*([^,]*)[,\s]+(?:tag|vlan_tag)[:\s]*(.*)/i
            ];

            let match = null;
            for (const pattern of patterns) {
                match = trimmedLine.match(pattern);
                if (match) break;
            }

            if (match) {
                interfaces.push({
                    name: match[1].trim(),
                    vlan_untag: match[2].trim(),
                    vlan_tag: match[3].trim()
            });
        }
    }
}

if (!interfaces || interfaces.length === 0) {
    tbody.innerHTML = '<tr><td colspan="3" style="text-align: center; color: #999;">No hay interfaces configuradas</td></tr>';
    return;
}

// Recargar cache como objeto indexado por nombre para compatibilidad
taggingCache = {};
interfaces.forEach(iface => {
    taggingCache[iface.name] = iface;
});

interfaces.forEach(iface => {
    const tr = document.createElement("tr");
    tr.setAttribute("data-name", iface.name);

    let vlanInfo = "";
    if (iface.vlan_untag) {
        vlanInfo = `<strong>UNTAG:</strong> ${iface.vlan_untag}`;
    }
    if (iface.vlan_tag) {
        if (vlanInfo) vlanInfo += "<br>";
        vlanInfo += `<strong>TAG:</strong> ${iface.vlan_tag}`;
    }

    let statusIcon = "✅";
    let statusHint = "";
    const ebtUsage = isInterfaceUsedByEbtables(iface.name);
    if (ebtUsage.used) {
        statusIcon = "⚠️";
        statusHint = ` (en uso por ebtables VLAN ${ebtUsage.vlanId})`;
    }

    tr.innerHTML = `
    <td>${statusIcon} ${iface.name}${statusHint}</td>
    <td>${vlanInfo}</td>
    <td>
    <button class="btn-edit" onclick="editRow('${iface.name}')">Modificar</button>
    <button class="btn-delete" onclick="deleteIface('${iface.name}')">Eliminar</button>
    </td>
    `;

        tbody.appendChild(tr);
    });

    const outputDiv = document.getElementById("output");
    if (outputDiv) outputDiv.textContent = "";

    } catch (err) {
        showMessage("❌ Error: " + err.message);
    }
}

function editRow(name) {
    const tr = document.querySelector(`tr[data-name="${name}"]`);
    const iface = taggingCache[name];

    if (!tr || !iface) {
        return;
    }

    tr.classList.add('edit-mode');
    tr.innerHTML = `
    <td>${iface.name}</td>
    <td>
    <label style="display: block; margin-bottom: 8px;">
    UNTAG: <input type="text" id="edit_untag_${name}" value="${iface.vlan_untag || ''}" placeholder="1-4094">
    </label>
    <label>
    TAG: <input type="text" id="edit_tag_${name}" value="${iface.vlan_tag || ''}" placeholder="1,2,3-10">
    </label>
    </td>
    <td>
    <button class="btn-save" onclick="saveRow('${name}')">Guardar</button>
    <button class="btn-cancel" onclick="cancelEdit()">Cancelar</button>
    </td>
    `;
}

async function saveRow(name) {
    const tr = document.querySelector(`tr[data-name="${name}"]`);
    const iface = taggingCache[name];

    let vlan_untag = (document.getElementById(`edit_untag_${name}`)?.value || "").trim();
    let vlan_tag = (document.getElementById(`edit_tag_${name}`)?.value || "").trim();

    vlan_untag = vlan_untag === "" ? "" : vlan_untag;
    vlan_tag = vlan_tag === "" ? "" : vlan_tag;

    if (vlan_untag) {
        if (!isValidVLANId(vlan_untag)) {
            showMessage(`❌ Error: VLAN Untag ${vlan_untag} no es válida. Debe estar entre 1 y 4094.`);
            return;
        }
        if (!isValidVLANExists(vlan_untag)) {
            showMessage(`⚠️ VLAN ${vlan_untag} no existe en vlans.json. Considere crearla primero.`);
        }
    }

    if (vlan_tag) {
        const validation = validateVLANList(vlan_tag);
        if (!validation.valid) {
            showMessage(`❌ Error en VLAN Tag: ${validation.errors.join(", ")}`);
            return;
        }
    }

    const atLeastOne = validateAtLeastOneVLAN(vlan_untag, vlan_tag);
    if (!atLeastOne.valid) {
        showMessage(`❌ Error: ${atLeastOne.error}`);
        return;
    }

    const noConflict = validateNoUNTAGandTAG(vlan_untag, vlan_tag);
    if (!noConflict.valid) {
        showMessage(`❌ Error: ${noConflict.error}`);
        return;
    }

    const ebtUsage = isInterfaceUsedByEbtables(name);
    if (ebtUsage.used) {
        showMessage(`⚠️ Advertencia: Interfaz ${name} está siendo usada por ebtables en VLAN ${ebtUsage.vlanId}. Modifique con cuidado.`);
    }

    try {
        const response = await fetch("/admin/tagging", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            credentials: "include",
            body: JSON.stringify({
                action: "config",
                params: {
                    action: "add",
                    name: name,
                    vlan_untag: vlan_untag,
                    vlan_tag: vlan_tag
                }
            })
    });

    const data = await response.json();

    if (!response.ok) {
        showMessage("❌ " + (data.detail || data.message || "Error desconocido"));
        return;
    }

    showMessage("✅ " + (data.message || "Interfaz guardada exitosamente"));
    loadAllData();

} catch (err) {
    showMessage("❌ Error: " + err.message);
}
}

function cancelEdit() {
    loadTagging();
}

async function deleteIface(name) {
    const ebtUsage = isInterfaceUsedByEbtables(name);
    if (ebtUsage.used) {
        if (!confirm(`⚠️ ADVERTENCIA: Esta interfaz está siendo usada por ebtables en VLAN ${ebtUsage.vlanId}.\n\n¿Desea continuar con la eliminación?`)) {
            return;
        }
    }

    if (!confirm(`¿Eliminar interfaz ${name}?`)) return;

    try {
        const response = await fetch("/admin/tagging", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            credentials: "include",
            body: JSON.stringify({
                action: "config",
                params: {
                    action: "remove",
                    name: name
                }
            })
    });

    const data = await response.json();

    if (!response.ok) {
        showMessage("❌ " + (data.detail || data.message || "Error eliminando interfaz"));
    } else {
        showMessage("✅ " + (data.message || "Interfaz eliminada exitosamente"));
    }

    loadAllData();

    } catch (err) {
        showMessage("❌ Error: " + err.message);
    }
}

/* -----------------------------
Inicialización cuando el DOM está listo
----------------------------- */

document.addEventListener("DOMContentLoaded", function() {
    const taggingForm = document.getElementById("taggingForm");
    
    taggingForm.addEventListener("submit", async (e) => {
    e.preventDefault();

    const form = e.target;
    const name = form.name.value.trim();
    let vlan_untag = form.vlan_untag.value.trim();
    let vlan_tag = form.vlan_tag.value.trim();

    if (!name) {
        showMessage("❌ Error: Nombre de interfaz no puede estar vacío");
        return;
    }

    if (!isValidInterfaceName(name)) {
        showMessage("❌ Error: Formato de interfaz inválido. Use caracteres alfanuméricos, guiones, puntos o barras bajas.");
        return;
    }

    // No normalizar a string vacío, dejar como está para el backend
    vlan_untag = vlan_untag === "" ? "" : vlan_untag;
    vlan_tag = vlan_tag === "" ? "" : vlan_tag;

    if (vlan_untag) {
        if (!isValidVLANId(vlan_untag)) {
            showMessage(`❌ Error: VLAN Untag ${vlan_untag} no es válida. Debe estar entre 1 y 4094.`);
            return;
        }
        if (!isValidVLANExists(vlan_untag)) {
            showMessage(`⚠️ VLAN ${vlan_untag} no existe en vlans.json. Considere crearla primero.`);
        }
    }

    if (vlan_tag) {
        const validation = validateVLANList(vlan_tag);
        if (!validation.valid) {
            showMessage(`❌ Error en VLAN Tag: ${validation.errors.join(", ")}`);
            return;
        }
    }

    const atLeastOne = validateAtLeastOneVLAN(vlan_untag, vlan_tag);
    if (!atLeastOne.valid) {
        showMessage(`❌ Error: ${atLeastOne.error}`);
        return;
    }

    const noConflict = validateNoUNTAGandTAG(vlan_untag, vlan_tag);
    if (!noConflict.valid) {
        showMessage(`❌ Error: ${noConflict.error}`);
        return;
    }

    try {
        const response = await fetch("/admin/tagging", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            credentials: "include",
            body: JSON.stringify({
                action: "config",
                params: {
                    action: "add",
                    name: name,
                    vlan_untag: vlan_untag,
                    vlan_tag: vlan_tag
                }
            })
    });

    const data = await response.json();

    if (!response.ok) {
        const errorMsg = data.detail || data.message || "Error desconocido";
        showMessage("❌ " + errorMsg);
        return;
    }

    showMessage("✅ " + (data.message || "Interfaz guardada exitosamente"));

    form.reset();
    loadAllData();

    } catch (err) {
        showMessage("❌ Error: " + err.message);
    }
    });

    // Cargar datos iniciales
    loadAllData();
});