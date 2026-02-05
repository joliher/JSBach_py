/* /web/00-js/expect/menu.js */
function runExpect(event, action, btn) {
    if (event) {
        event.preventDefault();
        event.stopPropagation();
    }
    const iframe = window.parent.frames["body"];
    if (!iframe) return;
    const botones = document.querySelectorAll("button");
    botones.forEach(b => b.classList.remove("selected"));
    if (btn) {
        btn.classList.add("selected");
        sessionStorage.setItem("expectSelected", btn.id);
    }
    if (action === "config") {
        iframe.location.href = "/web/expect/config.html";
    }
}
function runSecurity(event, btn) {
    if (event) {
        event.preventDefault();
        event.stopPropagation();
    }
    const iframe = window.parent.frames["body"];
    if (!iframe) return;
    document.querySelectorAll("button").forEach(b => b.classList.remove("selected"));
    if (btn) {
        btn.classList.add("selected");
        sessionStorage.setItem("expectSelected", btn.id);
    }
    iframe.location.href = "/web/expect/security.html";
}
function openInfo(event, btn) {
    if (event) {
        event.preventDefault();
        event.stopPropagation();
    }
    const iframe = window.parent.frames["body"];
    if (!iframe) return;
    document.querySelectorAll("button").forEach(b => b.classList.remove("selected"));
    if (btn) {
        btn.classList.add("selected");
        sessionStorage.setItem("expectSelected", btn.id);
    }
    iframe.location.href = "/web/expect/info.html";
}
window.addEventListener("DOMContentLoaded", () => {
    const saved = sessionStorage.getItem("expectSelected");
    const btnConfig = document.getElementById("btnConfig");
    const btnInfo = document.getElementById("btnInfo");
    if (saved === "btnInfo") {
        openInfo(null, btnInfo);
    } else {
        runExpect(null, "config", btnConfig);
    }
});
