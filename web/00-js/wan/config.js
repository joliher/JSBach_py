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

function isValidInterfaceName(iface) {
    // Valida que sea alfanumérico, guiones y puntos (eth0, ens3, enp0s3, wlan0, etc)
    return /^[a-zA-Z0-9._-]+$/.test(iface);
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
    const form = document.getElementById("wanForm");
    const modeSelect = document.getElementById("mode");
    const manualFields = document.getElementById("manualFields");
    const resultDiv = document.getElementById("result");

    /* -----------------------------
    Cargar configuración WAN
    ----------------------------- */
    async function loadWanConfiguration() {
        try {
            const response = await fetch("/config/wan/wan.json", {
                credentials: "include"
            });

            if (response.ok) {
                const wanConfig = await response.json();
                const wanInterface = wanConfig.interface || "No configurada";
                const wanMode = wanConfig.mode || "No definido";
                const wanStatus = wanConfig.status === 1 ? "Activo" : "Inactivo";

                let details = `${wanInterface} (Modo: ${wanMode}, Estado: ${wanStatus})`;

                document.getElementById("wan-details").textContent = details;
                document.getElementById("wan-info-container").style.display = "block";

                // Mostrar aviso de DHCP si el modo es DHCP
                const dhcpNotice = document.getElementById("dhcp-notice");
                if (wanMode === "dhcp") {
                    dhcpNotice.style.display = "block";
                } else {
                    dhcpNotice.style.display = "none";
                }

                // Pre-rellenar el formulario con la configuración actual
                if (wanInterface !== "No configurada") {
                    document.getElementById("interface").value = wanInterface;
                }

                if (wanMode === "manual" || wanMode === "dhcp") {
                    document.getElementById("mode").value = wanMode;
                    manualFields.classList.toggle("hidden", wanMode !== "manual");

                    if (wanMode === "manual") {
                        document.getElementById("ip").value = wanConfig.ip || "";
                        document.getElementById("mask").value = wanConfig.mask || "";
                        document.getElementById("gateway").value = wanConfig.gateway || "";
                        document.getElementById("dns").value = wanConfig.dns || "";
                    }
                }
            } else {
                // No hay configuración previa, mostrar formulario vacío
                console.info("No hay configuración WAN previa, mostrando formulario vacío");
            }
        } catch (err) {
            // Error al cargar configuración (probablemente no existe archivo)
            console.info("No se pudo cargar configuración WAN:", err.message);
            // Permitir que el usuario configure desde cero
        }
    }

    // Cargar configuración WAN al iniciar
    loadWanConfiguration();

    modeSelect.addEventListener("change", () => {
        manualFields.classList.toggle(
            "hidden",
            modeSelect.value !== "manual"
            );

            // Mostrar/ocultar aviso DHCP según el modo seleccionado
            const dhcpNotice = document.getElementById("dhcp-notice");
            if (modeSelect.value === "dhcp") {
                dhcpNotice.style.display = "block";
            } else {
                dhcpNotice.style.display = "none";
            }
        });

    form.addEventListener("submit", async (e) => {
        e.preventDefault();
        resultDiv.textContent = "";
        resultDiv.style.display = "none";

        const iface = document.getElementById("interface").value.trim();
        const mode = modeSelect.value;

        if (!iface) {
            return showError("❌ La interfaz no puede estar vacía");
        }

        if (!isValidInterfaceName(iface)) {
            return showError("❌ Formato de interfaz inválido. Use caracteres alfanuméricos, guiones o puntos (ej: eth0, ens3, enp0s3)");
        }

        const params = {
            interface: iface,
            mode: mode
        };

        if (mode === "manual") {
            const ip = document.getElementById("ip").value.trim();
            const mask = document.getElementById("mask").value.trim();
            const gateway = document.getElementById("gateway").value.trim();
            const dns = document.getElementById("dns").value.trim();

            if (!ip) {
                return showError("❌ IP no puede estar vacía");
            }
            if (!isValidIPv4(ip)) {
                return showError(`❌ IP inválida: ${ip}. Use formato válido (ej: 192.168.1.10)`);
            }
            if (!mask) {
                return showError("❌ Máscara (CIDR) no puede estar vacía");
            }
            if (!isValidCIDR(mask)) {
                return showError("❌ Máscara inválida. Use un valor entre 0 y 32 (ej: 24 para /24)");
            }
            if (!gateway) {
                return showError("❌ Gateway no puede estar vacío");
            }
            if (!isValidIPv4(gateway)) {
                return showError(`❌ Gateway inválido: ${gateway}. Use formato válido (ej: 192.168.1.1)`);
            }
            if (!dns) {
                return showError("❌ DNS no puede estar vacío");
            }
            if (!isValidDNSList(dns)) {
                return showError(`❌ DNS inválido: ${dns}. Use IPs válidas separadas por comas (ej: 8.8.8.8,1.1.1.1)`);
            }

            params.ip = ip;
            params.mask = mask;
            params.gateway = gateway;
            params.dns = dns;
        }

        try {
            // Mostrar mensaje de carga
            resultDiv.style.display = "block";
            resultDiv.className = "info";
            resultDiv.textContent = "⏳ Guardando configuración...";

            const response = await fetch("/admin/wan", {
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
                // Si es error del servidor, mostrar con más contexto
                let errorMsg = data.detail || "Error desconocido";
                if (errorMsg.includes("no existe")) {
                    errorMsg = "❌ " + errorMsg + " Verifique con 'ip link show' qué interfaces están disponibles.";
                } else {
                    errorMsg = "❌ Error: " + errorMsg;
                }
                throw new Error(errorMsg);
            }

            showSuccess("✅ " + data.message);

            // Actualizar la información de la interfaz WAN configurada
            setTimeout(() => {
                loadWanConfiguration();
            }, 500);

        } catch (err) {
            showError(err.message || "Error al guardar la configuración");
        }
    });
});