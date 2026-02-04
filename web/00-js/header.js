// Redirige toda la ventana a la sección correspondiente
function irSeccion(section) {
    // Limpiar todas las variables de botones seleccionados en sessionStorage
    sessionStorage.removeItem('vlansSelected');
    sessionStorage.removeItem('firewallSelected');
    sessionStorage.removeItem('wanSelected');
    sessionStorage.removeItem('dmzSelected');
    sessionStorage.removeItem('natSelected');
    sessionStorage.removeItem('taggingSelected');
    sessionStorage.removeItem('ebtablesSelected');

    window.top.location.href = '/web/' + section + '/index.html';
}

// Logout: destruye sesión y redirige al login
function logout() {
    fetch("/logout", { method: "POST" })
    .then(() => {
        window.top.location.href = "/login";
    });
}

// Marca el botón activo según la sección actual
function marcarBotonActivo() {
    const path = window.top.location.pathname; // ventana completa
    document.querySelectorAll("button[data-action]").forEach(btn => {
        const action = btn.getAttribute("data-action");
        if (path.includes('/' + action + '/')) {
            btn.classList.add("active");
        } else {
            btn.classList.remove("active");
        }
    });
}

window.onload = marcarBotonActivo;