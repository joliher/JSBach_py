/* /web/00-js/expect/security.js */

document.addEventListener("DOMContentLoaded", function () {
    const form = document.getElementById('security-form');

    // Añadir primer bloque por defecto
    addSecurityBlock();

    if (form) {
        form.onsubmit = async (e) => {
            e.preventDefault();
            const output = document.getElementById('output');
            output.style.display = 'block';
            output.innerHTML = '';

            const ip = document.getElementById('target-ip').value.trim();
            const profile = document.getElementById('profile').value;
            const dryRun = document.getElementById('dry_run').checked;

            const blocks = document.querySelectorAll('.security-block');
            if (blocks.length === 0) {
                logOutput('❌ Debe añadir al menos una regla de seguridad.', 'error');
                return;
            }

            logOutput('⏳ Iniciando aplicación de reglas de seguridad...', 'info');

            let successCount = 0;
            let errorCount = 0;

            for (let i = 0; i < blocks.length; i++) {
                const block = blocks[i];
                const ports = block.querySelector('.ports-input').value.trim();
                const macs = block.querySelector('.macs-input').value.trim();

                if (!ports || !macs) {
                    logOutput(`⚠️ Bloque #${i + 1} ignorado: Faltan puertos o MACs.`, 'warning');
                    continue;
                }

                // Validación tradicional: Comprobar espacios
                if (ports.includes(' ')) {
                    logOutput(`❌ Error en Bloque #${i + 1}: El campo de puertos contiene espacios ('${ports}'). Elimínelos (Ej: 1,2-4).`, 'error');
                    errorCount++;
                    continue;
                }

                logOutput(`🔄 Aplicando regla #${i + 1} (Puertos: ${ports})...`, 'info');

                const params = {
                    ip: ip,
                    profile: profile,
                    ports: ports,
                    macs: macs,
                    dry_run: dryRun
                };

                try {
                    const response = await fetch('/admin/expect', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ action: 'port-security', params })
                    });
                    const result = await response.json();

                    if (response.ok) {
                        logOutput(`✅ Regla #${i + 1} OK: ${result.message}`, 'success');
                        successCount++;
                    } else {
                        logOutput(`❌ Error Regla #${i + 1}: ${result.detail || result.message}`, 'error');
                        errorCount++;
                    }
                } catch (error) {
                    logOutput(`❌ Error de red procesando regla #${i + 1}: ${error.message}`, 'error');
                    errorCount++;
                }
            }

            logOutput(`🏁 Proceso finalizado. Éxitos: ${successCount}, Errores: ${errorCount}`, errorCount === 0 ? 'success' : 'warning');
        };
    }
});

let blockIdCounter = 0;

function addSecurityBlock() {
    const container = document.getElementById('security-blocks-container');
    const blockId = `sec-block-${blockIdCounter++}`;

    const div = document.createElement('div');
    div.className = 'security-block';
    div.id = blockId;

    div.innerHTML = `
        <button type="button" class="remove-block-btn" onclick="removeBlock('${blockId}')" title="Eliminar regla">×</button>
        
        <div class="form-group">
            <label>Puertos</label>
            <input type="text" class="ports-input" placeholder="Ej: 1,2-4,10" required>
            <small style="color: #7f8c8d;">Especifique puertos individuales o rangos separados por comas.</small>
        </div>
        
        <div class="form-group" style="margin-top: 15px;">
            <label>MACs Permitidas (Whitelist)</label>
            <textarea class="macs-input" placeholder="AA:BB:CC:DD:EE:FF&#10;00:11:22:33:44:55" rows="3" required style="width: 100%; padding: 10px; border: 1px solid #dcdde1; border-radius: 6px; font-family: monospace;"></textarea>
            <small style="color: #7f8c8d;">Separar MACs por espacios, comas o saltos de línea.</small>
        </div>
    `;

    container.appendChild(div);

    // Enfocar el nuevo input
    setTimeout(() => div.querySelector('.ports-input').focus(), 50);
}

function removeBlock(id) {
    const block = document.getElementById(id);
    if (block) block.remove();
}

function logOutput(msg, type) {
    const output = document.getElementById('output');
    const div = document.createElement('div');
    div.style.marginBottom = '5px';
    div.style.padding = '5px';
    div.style.borderRadius = '4px';

    if (type === 'error') {
        div.style.color = '#c0392b';
        div.style.backgroundColor = '#fadbd8';
    } else if (type === 'success') {
        div.style.color = '#27ae60';
        div.style.backgroundColor = '#d5f5e3';
    } else if (type === 'warning') {
        div.style.color = '#d35400';
        div.style.backgroundColor = '#fdebd0';
    } else {
        div.style.color = '#2c3e50';
    }

    div.innerText = msg;
    output.appendChild(div);
    output.scrollTop = output.scrollHeight;
}
