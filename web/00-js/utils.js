// utils.js - Funciones utilitarias comunes

/**
 * Hacer una petición HTTP y retornar JSON
 */
async function apiCall(endpoint, method = 'GET', data = null) {
    const options = {
        method: method,
        headers: {
            'Content-Type': 'application/json'
        }
    };

    if (data && (method === 'POST' || method === 'PUT')) {
        options.body = JSON.stringify(data);
    }

    try {
        const response = await fetch(endpoint, options);
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        return await response.json();
    } catch (error) {
        console.error('API Error:', error);
        throw error;
    }
}

/**
 * Obtener estado de un módulo
 */
async function getModuleStatus(module) {
    return apiCall(`/web/${module}/status`);
}

/**
 * Ejecutar una acción en un módulo
 */
async function executeModuleAction(module, action, params = {}) {
    return apiCall(`/web/${module}/action`, 'POST', { action, ...params });
}

/**
 * Mostrar notificación (toast)
 */
function showNotification(message, type = 'info', duration = 3000) {
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.textContent = message;
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: ${getColorByType(type)};
        color: white;
        padding: 16px 24px;
        border-radius: 4px;
        box-shadow: 0 4px 8px rgba(0,0,0,0.15);
        z-index: 9999;
        animation: slideIn 0.3s ease-out;
    `;

    document.body.appendChild(notification);

    if (duration > 0) {
        setTimeout(() => {
            notification.style.animation = 'slideOut 0.3s ease-in';
            setTimeout(() => notification.remove(), 300);
        }, duration);
    }
}

/**
 * Obtener color según tipo de notificación
 */
function getColorByType(type) {
    const colors = {
        success: '#4caf50',
        error: '#f44336',
        warning: '#ff9800',
        info: '#2196f3'
    };
    return colors[type] || colors.info;
}

/**
 * Mostrar modal de confirmación
 */
function showConfirmDialog(message, onConfirm, onCancel) {
    const modal = document.createElement('div');
    modal.className = 'modal-overlay';
    modal.innerHTML = `
        <div class="modal">
            <div class="modal-header">
                <h2>Confirmar acción</h2>
            </div>
            <div class="modal-body">
                <p>${message}</p>
            </div>
            <div class="modal-footer">
                <button class="btn btn-secondary" id="confirm-cancel">Cancelar</button>
                <button class="btn btn-danger" id="confirm-ok">Confirmar</button>
            </div>
        </div>
    `;

    document.body.appendChild(modal);

    document.getElementById('confirm-ok').addEventListener('click', () => {
        modal.remove();
        onConfirm();
    });

    document.getElementById('confirm-cancel').addEventListener('click', () => {
        modal.remove();
        onCancel && onCancel();
    });
}

/**
 * Formatear fecha/hora
 */
function formatDateTime(dateString) {
    const date = new Date(dateString);
    return date.toLocaleString('es-ES', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
    });
}

/**
 * Copiar texto al portapapeles
 */
async function copyToClipboard(text) {
    try {
        await navigator.clipboard.writeText(text);
        showNotification('Copiado al portapapeles', 'success', 2000);
    } catch (error) {
        console.error('Error copiando:', error);
        showNotification('Error al copiar', 'error');
    }
}

/**
 * Validar dirección IP
 */
function isValidIP(ip) {
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (!ipRegex.test(ip)) return false;
    
    const octets = ip.split('.');
    return octets.every(octet => {
        const num = parseInt(octet, 10);
        return num >= 0 && num <= 255;
    });
}

/**
 * Validar VLAN ID (1-4094)
 */
function isValidVLANID(id) {
    const num = parseInt(id, 10);
    return num >= 1 && num <= 4094;
}

/**
 * Validar puerto (1-65535)
 */
function isValidPort(port) {
    const num = parseInt(port, 10);
    return num >= 1 && num <= 65535;
}

/**
 * Animar elemento
 */
function animateElement(element, animationName, duration = 300) {
    element.style.animation = `${animationName} ${duration}ms ease-in-out`;
    setTimeout(() => {
        element.style.animation = '';
    }, duration);
}

/**
 * Debounce para búsqueda/filtrado
 */
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

/**
 * Actualizar tabla con datos
 */
function updateTable(tableSelector, data, columns) {
    const table = document.querySelector(tableSelector);
    if (!table) return;

    const tbody = table.querySelector('tbody');
    tbody.innerHTML = '';

    if (!data || data.length === 0) {
        tbody.innerHTML = '<tr><td colspan="' + columns.length + '">Sin datos</td></tr>';
        return;
    }

    data.forEach(item => {
        const row = document.createElement('tr');
        columns.forEach(col => {
            const cell = document.createElement('td');
            cell.textContent = item[col] || '-';
            row.appendChild(cell);
        });
        tbody.appendChild(row);
    });
}

/**
 * Agregar estilos de animación
 */
if (!document.getElementById('animation-styles')) {
    const style = document.createElement('style');
    style.id = 'animation-styles';
    style.textContent = `
        @keyframes slideIn {
            from {
                transform: translateX(400px);
                opacity: 0;
            }
            to {
                transform: translateX(0);
                opacity: 1;
            }
        }

        @keyframes slideOut {
            from {
                transform: translateX(0);
                opacity: 1;
            }
            to {
                transform: translateX(400px);
                opacity: 0;
            }
        }

        .modal-overlay {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0,0,0,0.5);
            display: flex;
            justify-content: center;
            align-items: center;
            z-index: 10000;
        }

        .modal {
            background: white;
            border-radius: 4px;
            box-shadow: 0 4px 16px rgba(0,0,0,0.2);
            max-width: 500px;
            width: 90%;
            overflow: hidden;
        }

        .modal-header {
            background: var(--primary-color);
            color: white;
            padding: 16px;
        }

        .modal-body {
            padding: 24px;
        }

        .modal-footer {
            display: flex;
            justify-content: flex-end;
            gap: 8px;
            padding: 16px;
            background: #f9f9f9;
        }
    `;
    document.head.appendChild(style);
}
