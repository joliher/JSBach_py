async function login() {
    const username = document.getElementById("username").value;
    const password = document.getElementById("password").value;
    const errorBox = document.getElementById("error");

    errorBox.textContent = "";

    if (!username || !password) {
        errorBox.textContent = "Introduce usuario y contraseña";
        return;
    }

    try {
        const response = await fetch("/login", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                username: username,
                password: password
            }),
            credentials: 'same-origin'  // Esto envía las cookies de sesión automáticamente
    });

    if (response.ok) {
        // Login correcto → ir a admin
        window.location.href = "/web/index.html";
    } else {
        const data = await response.json();
        errorBox.textContent = data.detail || "Error de autenticación";
    }

} catch (err) {
    errorBox.textContent = "No se pudo conectar con el servidor";
}
}

// Event listener para enviar formulario con Enter
document.addEventListener("DOMContentLoaded", function() {
    const inputs = document.querySelectorAll("input");
    inputs.forEach(input => {
        input.addEventListener("keypress", function(event) {
            if (event.key === "Enter") {
                event.preventDefault();
                login();
            }
    });
});
});