/* /web/00-js/expect/config.js */

let profileData = null;
let globalParams = {};
let interfaceParams = {};

document.addEventListener("DOMContentLoaded", async function () {
    const form = document.getElementById('expect-form');
    const targetIpInput = document.getElementById('target-ip');

    // Cargar perfil inicial
    await loadProfileParams();

    if (form) {
        form.onsubmit = async (e) => {
            e.preventDefault();
            const output = document.getElementById('output');
            output.style.display = 'block';
            output.style.color = '#00ff00';
            output.innerHTML = '⏳ Procesando orquestación...';

            const result = serializeActions();
            if (result.error || !result) {
                output.style.color = '#ff5555';
                output.innerHTML = result.error ? `❌ Errores en el formulario:<br><div style="text-align: left; margin-top: 10px; font-size: 13px;">${result.error}</div>` : '❌ Debe añadir al menos una configuración válida.';
                return;
            }
            const actions = result;

            const params = {
                ip: targetIpInput.value.trim(),
                profile: document.getElementById('profile').value,
                actions: actions,
                dry_run: document.getElementById('dry_run').checked,
                auth_required: document.getElementById('auth_required').checked
            };

            try {
                const response = await fetch('/admin/expect', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ action: 'config', params })
                });
                const result = await response.json();
                if (response.ok) {
                    output.innerHTML = result.message;
                } else {
                    output.style.color = '#ff5555';
                    output.innerHTML = '❌ Error: ' + (result.detail || result.message);
                }
            } catch (error) {
                output.style.color = '#ff5555';
                output.innerHTML = '❌ Error de red al conectar con el servidor';
            }
        };
    }

    // Listener para el aviso de autenticación
    const authCheckbox = document.getElementById('auth_required');
    if (authCheckbox) {
        authCheckbox.onchange = toggleAuthWarning;
        toggleAuthWarning(); // Estado inicial
    }
});

function toggleAuthWarning() {
    const checkbox = document.getElementById('auth_required');
    const warning = document.getElementById('auth-warning-box');
    if (checkbox && warning) {
        if (checkbox.checked) {
            warning.classList.remove('hidden');
        } else {
            warning.classList.add('hidden');
        }
    }
}

async function loadProfileParams() {
    const profileId = document.getElementById('profile').value;
    const globalCont = document.getElementById('global-config-container');
    const interfaceCont = document.getElementById('interface-config-container');

    // Comprobar si hay configuración previa para avisar al usuario
    const hasConfig = globalCont.querySelectorAll('.config-row').length > 0 ||
        interfaceCont.querySelectorAll('.config-block').length > 0;

    if (hasConfig && !confirm("Al cambiar de perfil se borrará la configuración actual. ¿Continuar?")) {
        // Nota: El select mantendrá el nuevo valor, pero no cargaremos los parámetros.
        // Lo ideal sería revertir el select, pero requiere guardar el estado anterior.
        return;
    }

    try {
        const response = await fetch(`/admin/expect/profiles/${profileId}`);
        if (!response.ok) throw new Error(`Error ${response.status}: No se pudo cargar el perfil.`);

        profileData = await response.json();

        // Clasificar parámetros
        globalParams = {};
        interfaceParams = {};
        for (let [key, val] of Object.entries(profileData.parameters)) {
            if (val.context === 'global') globalParams[key] = val;
            else interfaceParams[key] = val;
        }

        // Limpiar contenedores SOLO tras éxito en la carga
        globalCont.innerHTML = '';
        interfaceCont.innerHTML = '';
        globalCont.style.display = 'none';

        // Sincronizar checkbox de autenticación
        if (profileData && profileData.hasOwnProperty('auth_required')) {
            const authCheck = document.getElementById('auth_required');
            if (authCheck) {
                authCheck.checked = profileData.auth_required;
                toggleAuthWarning();
            }
        }

    } catch (error) {
        console.error("Error al cargar perfil:", error);
        alert("❌ Error: " + error.message);
    }
}

function showParamMenu(btn, context, blockId = null, parentKey = null) {
    // Cerrar otros menús primero
    document.querySelectorAll('.param-menu').forEach(m => m.style.display = 'none');

    const menu = btn.nextElementSibling;
    const params = context === 'global' ? globalParams : interfaceParams;

    let block = null;
    if (blockId) block = document.getElementById(blockId);

    // El contenedor de búsqueda de llaves usadas debe ser el correcto
    const container = context === 'global' ? document.getElementById('global-config-container') : block.querySelector('.interface-params-list');

    if (!container) return;

    const usedKeys = Array.from(container.querySelectorAll('.param-label')).map(l => l.getAttribute('data-key'));
    let available = Object.keys(params).filter(k => !usedKeys.includes(k));

    // RESTRICCIÓN: No TAG y UNTAG a la vez
    if (usedKeys.includes('tag')) {
        available = available.filter(k => k !== 'untag');
    }
    if (usedKeys.includes('untag')) {
        available = available.filter(k => k !== 'tag');
    }

    // NUEVA LÓGICA JERÁRQUICA VERTICAL (MODE -> VLAN o TAGGING)
    if (context === 'interface') {
        if (!parentKey) {
            // Menú principal: Solo MODE y DESCRIPTION
            available = available.filter(k => k === 'mode' || k === 'description');
        } else if (parentKey === 'mode') {
            // Menú de MODE depende del valor seleccionado
            const modeSelect = container.querySelector('.param-label[data-key="mode"]')?.parentElement.querySelector('select');
            const modeValue = modeSelect ? modeSelect.value : 'access';

            if (modeValue === 'access') {
                available = available.filter(k => k === 'vlan');
            } else {
                available = available.filter(k => k === 'tag' || k === 'untag');
            }
        }
    }

    if (available.length === 0) {
        alert("⚠️ No hay más parámetros disponibles para esta sección.");
        return;
    }

    let html = `<div class="menu-header">Añadir Parámetro</div>`;
    available.forEach(k => {
        // En contexto global, NO pasamos el contenedor override para que se use el global por defecto
        const override = context === 'global' ? 'null' : 'this.parentElement.parentElement';
        html += `<button type="button" onclick="addParamRow('${context}', '${k}', ${blockId ? `'${blockId}'` : 'null'}, ${override})">${k.toUpperCase()}</button>`;
    });

    menu.innerHTML = html;
    menu.style.display = 'block';

    const closer = (e) => {
        if (!menu.contains(e.target) && e.target !== btn) {
            menu.style.display = 'none';
            document.removeEventListener('click', closer);
        }
    };
    setTimeout(() => document.addEventListener('click', closer), 10);
}

function addParamRow(context, key, blockId = null, containerOverride = null) {
    const params = context === 'global' ? globalParams : interfaceParams;
    let mainContainer;
    if (context === 'global') {
        mainContainer = document.getElementById('global-config-container');
    } else {
        mainContainer = document.getElementById(blockId).querySelector('.interface-params-list');
    }

    const container = containerOverride || mainContainer;

    const wrapper = document.createElement('div');
    wrapper.className = 'param-wrapper';

    const row = document.createElement('div');
    row.className = 'config-row';

    const paramDef = params[key];
    let inputHtml = '';

    if (paramDef && paramDef.validation && paramDef.validation.trim().startsWith('enum:')) {
        const options = paramDef.validation.replace('enum:', '').split(',');
        inputHtml = `<select required style="flex: 1; padding: 10px; border-radius: 6px; border: 1px solid #dcdde1;">`;
        options.forEach(opt => {
            inputHtml += `<option value="${opt}">${opt}</option>`;
        });
        inputHtml += `</select>`;
    } else {
        let placeholder = `Valor para ${key}`;
        if (["vlan", "tag", "untag"].includes(key)) placeholder = "Ej: 10, 20-30";

        // TAG y UNTAG no son obligatorios
        const isRequired = !["tag", "untag"].includes(key);
        inputHtml = `<input type="text" placeholder="${placeholder}" ${isRequired ? 'required' : ''} style="flex: 1;">`;
    }

    row.innerHTML = `
        <div class="param-label" data-key="${key}">${key.toUpperCase()}</div>
        ${inputHtml}
        <button type="button" class="btn-icon" style="${context !== 'global' ? 'width: 25px; height: 25px;' : ''}" onclick="removeRow(this)">🗑️</button>
    `;

    wrapper.appendChild(row);

    // Contenedor de hijos para parámetros con descendencia (Ahora solo MODE tiene hijos)
    if (context === 'interface' && key === 'mode') {
        const childContainer = document.createElement('div');
        childContainer.className = 'child-params-container';

        const triggerBtn = `
            <div class="add-param-container child-param-trigger" data-parent="${key}" style="display: none;">
                <button type="button" class="btn btn-blue btn-small" onclick="addChildParams('${context}', '${key}', '${blockId}', this)">Añadir ...</button>
            </div>
        `;
        childContainer.innerHTML = triggerBtn;
        wrapper.appendChild(childContainer);
    }

    container.appendChild(wrapper);

    // Listener especial para MODE
    if (key === 'mode' && context === 'interface') {
        const select = row.querySelector('select');
        if (select) {
            select.onchange = () => handleModeChange(select, blockId);
            setTimeout(() => handleModeChange(select, blockId), 50);
        }
    }

    // Asegurar que el contenedor global sea visible si se añade algo
    if (context === 'global') {
        const globalCont = document.getElementById('global-config-container');
        if (globalCont) globalCont.style.display = 'block';
    }

    // Cerrar el menú
    document.querySelectorAll('.param-menu').forEach(m => m.style.display = 'none');
}

let interfaceBlockId = 0;
function addInterfaceBlock() {
    const container = document.getElementById('interface-config-container');
    const blockId = `interface-block-${interfaceBlockId++}`;

    const div = document.createElement('div');
    div.className = 'config-block';
    div.id = blockId;

    div.innerHTML = `
        <div class="config-row" style="margin-bottom: 10px; align-items: center;">
            <div class="param-label" style="background: #f1f2f6; color: #2c3e50; border-color: #dcdde1;">PUERTOS</div>
            <input type="text" class="port-input" placeholder="Ej: 1-4, 6, 8-10 (solo números, comas y guiones)" required style="flex: 1;" pattern="^[0-9,\\-\\s,]+$" title="Solo se permiten números, comas, guiones y espacios. No incluya prefijos como 'puerto:'">
            <button type="button" class="btn-icon" style="width: 25px; height: 25px;" onclick="removeRow(this)">🗑️</button>
        </div>
        
        <div class="interface-params-list"></div>
        
        <div class="add-param-container" style="margin-top: 10px; margin-left: 5px;">
            <button type="button" class="btn btn-blue btn-small" onclick="showParamMenu(this, 'interface', '${blockId}')">➕ Añadir Parámetro</button>
            <div class="param-menu"></div>
        </div>
        
        <div style="margin-top: 15px; border-bottom: 1px solid #eee;"></div>
    `;
    container.appendChild(div);

    // Auto-añadir el parámetro maestro (MODE) para guiar al usuario
    addParamRow('interface', 'mode', blockId);

    // Enfocar el input de puertos para agilizar la entrada
    setTimeout(() => div.querySelector('.port-input').focus(), 100);
}

function handleModeChange(select, blockId) {
    const mode = select.value;
    const block = document.getElementById(blockId);
    if (!block) return;

    const row = select.closest('.param-wrapper');
    const trigger = row.querySelector('.child-param-trigger[data-parent="mode"]');
    if (!trigger) return;

    const btn = trigger.querySelector('button');

    // Buscar si ya existen los hijos
    const hasVlan = block.querySelector('.param-label[data-key="vlan"]');
    const hasTagging = block.querySelector('.param-label[data-key="tag"]') || block.querySelector('.param-label[data-key="untag"]');

    if (mode === 'access') {
        // En modo access, mostrar botón para añadir VLAN
        btn.innerHTML = "➕ Añadir VLAN";
        trigger.style.display = hasVlan ? 'none' : 'block';

        // Limpiar tagging si existe
        const tagRow = block.querySelector('.param-label[data-key="tag"]')?.closest('.param-wrapper');
        const untagRow = block.querySelector('.param-label[data-key="untag"]')?.closest('.param-wrapper');
        if (tagRow) tagRow.remove();
        if (untagRow) untagRow.remove();
    } else {
        // En modo trunk/general, mostrar botón para añadir TAGGING
        btn.innerHTML = "➕ Añadir TAGGING";
        trigger.style.display = hasTagging ? 'none' : 'block';

        // Limpiar vlan si existe
        const vlanRow = block.querySelector('.param-label[data-key="vlan"]')?.closest('.param-wrapper');
        if (vlanRow) vlanRow.remove();
    }
}

function addChildParams(context, parentKey, blockId, btn) {
    const container = btn.parentElement.parentElement; // .child-params-container
    const block = document.getElementById(blockId);

    if (parentKey === 'mode') {
        const modeSelect = block.querySelector('.param-label[data-key="mode"]')?.parentElement.querySelector('select');
        const modeValue = modeSelect ? modeSelect.value : 'access';

        if (modeValue === 'access') {
            addParamRow(context, 'vlan', blockId, container);
        } else {
            addParamRow(context, 'tag', blockId, container);
            addParamRow(context, 'untag', blockId, container);
        }
    }

    // Ocultar el botón tras pulsar
    btn.parentElement.style.display = 'none';
}

function removeRow(btn) {
    const wrapper = btn.closest('.param-wrapper');
    const row = btn.closest('.config-row');
    const block = btn.closest('.config-block');

    if (row) {
        const label = row.querySelector('.param-label');
        const key = label ? label.getAttribute('data-key') : null;
        const isPortsRow = label && label.textContent === 'PUERTOS';

        // Si es la fila de PUERTOS, borrar todo el bloque
        if (isPortsRow && block) {
            block.remove();
            return;
        }

        // Al borrar hijos de MODE, restaurar el botón correspondiente
        if ((key === 'vlan' || key === 'tag' || key === 'untag') && block) {
            const modeTrigger = block.querySelector('.child-param-trigger[data-parent="mode"]');
            const modeSelect = block.querySelector('.param-label[data-key="mode"]')?.parentElement.querySelector('select');
            const modeValue = modeSelect ? modeSelect.value : null;

            if (modeTrigger && modeValue) {
                if (modeValue === 'access' && key === 'vlan') {
                    modeTrigger.style.display = 'block';
                } else if ((modeValue === 'trunk' || modeValue === 'general')) {
                    const hasOtherTagging = (key === 'tag' && block.querySelector('.param-label[data-key="untag"]')) ||
                        (key === 'untag' && block.querySelector('.param-label[data-key="tag"]'));
                    if (!hasOtherTagging) modeTrigger.style.display = 'block';
                }
            }
        }

        if (wrapper) {
            wrapper.remove();
        } else {
            row.remove();
        }

        // Si el contenedor global se queda vacío, ocultarlo
        const globalCont = document.getElementById('global-config-container');
        if (globalCont && globalCont.querySelectorAll('.config-row').length === 0) {
            globalCont.style.display = 'none';
        }
    } else if (block) {
        block.remove();
    }
}

function serializeActions() {
    let parts = [];
    let errors = [];

    // Global
    const globalRows = document.querySelectorAll('#global-config-container .config-row');
    if (globalRows.length > 0) {
        let globalParamsList = [];
        globalRows.forEach(row => {
            const label = row.querySelector('.param-label');
            const k = label ? label.getAttribute('data-key') : null;
            const input = row.querySelector('input') || row.querySelector('select');
            const v = input ? input.value.trim() : "";
            if (k) {
                if (v) globalParamsList.push(`${k}:${v}`);
                else errors.push(`Configuración Global: El campo '${k.toUpperCase()}' está vacío.`);
            }
        });
        if (globalParamsList.length > 0) parts.push(globalParamsList.join(','));
    }

    // Interfaces
    const interfaceBlocks = document.querySelectorAll('#interface-config-container .config-block');
    interfaceBlocks.forEach((block, idx) => {
        const portsInput = block.querySelector('.port-input');
        const ports = portsInput ? portsInput.value.trim() : "";
        const blockName = ports ? `Bloque '${ports}'` : `Bloque de Puertos #${idx + 1}`;

        if (!ports) {
            errors.push(`${blockName}: No se han definido los puertos.`);
        }

        const rows = block.querySelectorAll('.interface-params-list .config-row');
        let blockParams = [];
        rows.forEach(row => {
            const label = row.querySelector('.param-label');
            const k = label ? label.getAttribute('data-key') : null;
            const input = row.querySelector('input') || row.querySelector('select');
            const v = input ? input.value.trim() : "";
            if (k) {
                // TAG y UNTAG son opcionales (tienen el atributo required dinámico)
                const isRequired = input.hasAttribute('required');
                if (v) blockParams.push(`${k}:${v}`);
                else if (isRequired) errors.push(`${blockName}: El campo '${k.toUpperCase()}' es obligatorio.`);
            }
        });

        // REQUISITO: Si el modo es 'general', DEBE haber al menos un 'tag' o 'untag' con valor
        const modeParam = blockParams.find(p => p.startsWith('mode:'));
        if (modeParam === 'mode:general') {
            const hasTag = blockParams.some(p => p.startsWith('tag:'));
            const hasUntag = blockParams.some(p => p.startsWith('untag:'));
            if (!hasTag && !hasUntag) {
                errors.push(`${blockName}: El modo 'GENERAL' requiere especificar al menos un parámetro 'TAG' o 'UNTAG'.`);
            }
        }

        if (ports && blockParams.length > 0) {
            parts.push(`ports:${ports},${blockParams.join(',')}`);
        }
    });

    if (errors.length > 0) return { error: errors.join('<br>') };
    return parts.join(' / ');
}

window.openAuth = () => {
    const ip = document.getElementById('target-ip').value.trim();
    if (!ip) {
        alert("⚠️ Por favor, introduzca primero la IP del switch.");
        return;
    }
    document.getElementById('modal-target-ip').textContent = ip;
    document.getElementById('auth-modal').style.display = 'block';
    document.getElementById('modal-overlay').style.display = 'block';
};

window.closeAuth = () => {
    document.getElementById('auth-modal').style.display = 'none';
    document.getElementById('modal-overlay').style.display = 'none';
};

window.saveAuth = async () => {
    const ip = document.getElementById('target-ip').value.trim();
    const user = document.getElementById('auth-user').value.trim();
    const pass = document.getElementById('auth-pass').value.trim();

    if (!user || !pass) {
        alert("⚠️ Usuario y contraseña son obligatorios");
        return;
    }

    try {
        const response = await fetch('/admin/expect', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                action: 'auth',
                params: { ip, user, password: pass }
            })
        });
        const result = await response.json();
        alert(result.message);
        if (response.ok) window.closeAuth();
    } catch (error) {
        alert('❌ Error guardando credenciales');
    }
};
// ... (código existente)

window.handleSoftReset = async () => {
    const ip = document.getElementById('target-ip').value.trim();
    if (!ip) {
        alert("⚠️ Por favor, introduzca primero la IP del switch.");
        return;
    }

    // 1. Primera confirmación
    if (!confirm("⚠️ ¡ATENCIÓN! ESTA ACCIÓN ES DESTRUCTIVA.\n\nSe restablecerán TODAS las interfaces físicas a su configuración por defecto.\nLas configuraciones de VLANs, Trunks y modos se perderán.\n\nLa gestión IP se mantendrá intacta.\n\n¿Está seguro de que desea continuar?")) {
        return;
    }

    // 2. Segunda confirmación de seguridad
    const validation = prompt("Para confirmar, escriba 'RESET' en mayúsculas:");
    if (validation !== 'RESET') {
        alert("❌ Operación cancelada. El código de confirmación no coincide.");
        return;
    }

    const output = document.getElementById('output');
    output.style.display = 'block';
    output.style.color = '#e67e22';
    output.innerHTML = '⏳ [SOFT RESET] Limpiando interfaces... Por favor espere.';

    const params = {
        ip: ip,
        profile: document.getElementById('profile').value,
        dry_run: document.getElementById('dry_run').checked,
        auth_required: document.getElementById('auth_required').checked
    };

    try {
        const response = await fetch('/admin/expect', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action: 'reset', params })
        });
        const result = await response.json();

        if (response.ok) {
            output.style.color = '#27ae60';
            output.innerHTML = '✅ ' + result.message.replace(/\n/g, '<br>');
        } else {
            output.style.color = '#e74c3c';
            output.innerHTML = '❌ ' + (result.detail || result.message);
        }
    } catch (error) {
        output.style.color = '#e74c3c';
        output.innerHTML = '❌ Error crítico de comunicación con el servidor.';
    }
};
