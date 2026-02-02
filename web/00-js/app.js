// app.js - Lógica principal de la aplicación

/**
 * Cargar estado inicial de todos los módulos
 */
async function loadModuleStatuses() {
    const modules = ['wan', 'vlans', 'firewall', 'nat', 'dmz', 'tagging'];
    const container = document.getElementById('status-container');
    container.innerHTML = '';

    for (const module of modules) {
        try {
            const response = await apiCall(`/web/api/${module}/status`, 'GET');
            const status = response.status || 0;
            const statusClass = status === 1 ? 'active' : 'inactive';
            const statusText = status === 1 ? 'Activo' : 'Inactivo';

            const statusItem = document.createElement('div');
            statusItem.className = `status-item ${statusClass}`;
            statusItem.innerHTML = `
                <span class="status-indicator ${statusClass}"></span>
                <strong>${module.toUpperCase()}</strong>
                <small style="display: block; margin-top: 4px; color: #666;">
                    ${statusText}
                </small>
            `;
            container.appendChild(statusItem);
        } catch (error) {
            console.error(`Error cargando status de ${module}:`, error);
        }
    }
}

/**
 * Cargar contenido de un módulo
 */
async function loadModuleContent(module) {
    const content = document.getElementById('module-content');
    content.innerHTML = '<p>Cargando...</p>';

    try {
        const response = await fetch(`/web/${module}/index.html`);
        if (!response.ok) throw new Error('Módulo no encontrado');
        
        const html = await response.text();
        content.innerHTML = html;
        
        // Ejecutar script del módulo si existe
        const script = content.querySelector('script');
        if (script) {
            eval(script.textContent);
        }
    } catch (error) {
        content.innerHTML = `
            <div class="card alert-danger">
                <div class="card-header">Error</div>
                <div class="card-body">
                    <p>No se pudo cargar el módulo ${module}.</p>
                    <p>${error.message}</p>
                </div>
            </div>
        `;
    }
}

/**
 * Inicializar evento de navegación
 */
function initializeNavigation() {
    document.querySelectorAll('.nav-link').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const module = e.target.dataset.module;
            
            // Actualizar link activo
            document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
            e.target.classList.add('active');
            
            // Cargar contenido
            loadModuleContent(module);
        });
    });
}

/**
 * Inicialización al cargar la página
 */
document.addEventListener('DOMContentLoaded', () => {
    initializeNavigation();
    loadModuleStatuses();
    
    // Actualizar estado cada 10 segundos
    setInterval(loadModuleStatuses, 10000);
});
