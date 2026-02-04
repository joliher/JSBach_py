/* -----------------------------
Utilidades de validación
----------------------------- */

function isValidIPv4(ip) {
    const regex =
    /^(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)){3}$/;
    return regex.test(ip);
}

function isValidCIDR(mask) {
    const n = Number(mask);
    return Number.isInteger(n) && n >= 0 && n <= 32;
}

function isValidDNSList(dns) {
    const servers = dns.split(",").map(d => d.trim()).filter(Boolean);
    if (servers.length === 0) return false;
    return servers.every(isValidIPv4);
}

function showError(msg) {
    const resultDiv = document.getElementById("result");
    resultDiv.style.display = "block";
    resultDiv.className = "error";
    resultDiv.textContent = msg;
}

function showSuccess(msg) {
    const resultDiv = document.getElementById("result");
    resultDiv.style.display = "block";
    resultDiv.className = "success";
    resultDiv.textContent = msg;
}

/* -----------------------------
Inicialización cuando el DOM está listo
----------------------------- */

document.addEventListener("DOMContentLoaded", function() {
    const form = document.getElementById("natForm");
    const resultDiv = document.getElementById("result");

    /* -----------------------------
    Cargar interfaz WAN
    ----------------------------- */
    async function loadWanInterface() {
    try {
        const response = await fetch("/config/wan/wan.json", {
            credentials: "include"
    });

    if (response.ok) {
        const wanConfig = await response.json();
        const wanInterface = wanConfig.interface || "No configurada";
        const wanMode = wanConfig.mode || "No definido";

        document.getElementById("wan-details").textContent = `${wanInterface} (Modo: ${wanMode})`;
        document.getElementById("wan-info-container").style.display = "block";
    }
} catch (err) {
    console.info("No se pudo cargar configuración WAN:", err.message);
}
}

    /* -----------------------------
    Cargar interfaz NAT
    ----------------------------- */
    async function loadNatInterface() {
    try {
        const response = await fetch("/config/nat/nat.json", {
            credentials: "include"
    });

    if (response.ok) {
        const natConfig = await response.json();
        const natInterface = natConfig.interface || "No configurada";
        const natStatus = natConfig.status === 1 ? "Activo" : "Inactivo";

        document.getElementById("nat-details").textContent = `${natInterface} (Estado: ${natStatus})`;
        document.getElementById("nat-info-container").style.display = "block";

        // Pre-rellenar el campo de interfaz con la configuración actual
        if (natInterface !== "No configurada") {
            document.getElementById("interface").value = natInterface;
        }
    }
    } catch (err) {
        console.info("No se pudo cargar configuración NAT:", err.message);
    }
    }

    // Cargar interfaz WAN al iniciar
    loadWanInterface();

    // Cargar interfaz NAT al iniciar
    loadNatInterface();

    form.addEventListener("submit", async (e) => {
        e.preventDefault();
        resultDiv.style.display = "none";
        resultDiv.textContent = "";
    const iface = document.getElementById("interface").value.trim();

    if (!iface) {
        return showError("La interfaz no puede estar vacía");
    }

    const params = {
        interface: iface
    };

    try {
        const response = await fetch("/admin/nat", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            credentials: "include",
            body: JSON.stringify({
                action: "config",
                params: params
            })
    });

    const data = await response.json();

    if (!response.ok) {
        throw new Error(data.detail || "Error desconocido");
    }

    showSuccess(data.message);

    // Actualizar la información de la interfaz NAT configurada
    await loadNatInterface();

    } catch (err) {
        showError(err.message);
    }
    });
});