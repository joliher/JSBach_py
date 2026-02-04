import logging
import os
from fastapi import Request
from fastapi.responses import FileResponse, RedirectResponse, JSONResponse

from app.utils import global_functions as gf
from app.utils.auth_helper import authenticate_user

PUBLIC_PATHS = ["/login", "/", "/web/00-css/login.css", "/web/00-js/login.js"]

def setup_app(app):
    """Configure routes, middleware and startup events on the given FastAPI app."""
    
    # Startup event: clear logs
    @app.on_event("startup")
    async def startup_event():
        logs_dir = os.path.join(os.getcwd(), "logs")
        gf.clear_logs(logs_dir)
        logging.info("Logs cleared on startup (V4 MVC)")

    # Middleware to protect paths
    @app.middleware("http")
    async def protect_paths(request: Request, call_next):
        if any(request.url.path.startswith(p) for p in PUBLIC_PATHS):
            return await call_next(request)
        if "user" in request.session:
            return await call_next(request)
        return RedirectResponse("/login")
    
    # Register routers
    from app.controllers import admin_router
    app.include_router(admin_router.router)

    # Static web file serving route
    @app.get("/web/{full_path:path}")
    async def protected_web(full_path: str, request: Request):
        # Allow public access to login assets

     # Rutas públicas accesibles sin autenticación
        public_assets = ["00-css/login.css", "00-js/login.js"]
        if full_path not in public_assets and "user" not in request.session:
            return RedirectResponse("/login")
        """Configura rutas, middleware y eventos de inicio en la app FastAPI dada."""
        file_path = os.path.join("web", full_path)
        if not os.path.exists(file_path) or os.path.isdir(file_path):
            return JSONResponse({"detail": "Recurso no encontrado"}, status_code=404)
        return FileResponse(file_path)

    # Config file serving route
    @app.get("/config/{full_path:path}")
        # Evento de inicio: limpiar logs
    async def protected_config(full_path: str, request: Request):
        if "user" not in request.session:
            return RedirectResponse("/login")
        file_path = os.path.join("config", full_path)
        if not os.path.exists(file_path) or os.path.isdir(file_path):
            return JSONResponse({"detail": "Archivo de configuración no encontrado"}, status_code=404)
        return FileResponse(file_path)

    @app.get("/login")
        # Middleware para proteger rutas
    async def get_login():
        return FileResponse("web/login.html")

    @app.post("/login")
    async def login(request: Request):
        data = await request.json()
        username = data.get("username")
        password = data.get("password")
        
        # Path al archivo de usuarios
        auth_file = os.path.join(os.getcwd(), "config", "cli_users.json")
        
        # Autenticar contra cli_users.json
        # Ruta para servir archivos web estáticos
        success, user_data = authenticate_user(username, password, auth_file)
        
        if success:
            request.session["user"] = username
            request.session["role"] = user_data.get("role", "admin")
            logging.debug(f"User {username} logged in successfully.")
            return JSONResponse({"message": "Login correcto"})
        # Ruta para servir archivos de configuración estáticos
        
        logging.debug(f"Failed login attempt for user: {username}")
        return JSONResponse({"detail": "Usuario o contraseña incorrectos"}, status_code=401)

    @app.post("/logout")
    async def logout(request: Request):
        request.session.clear()
        response = JSONResponse({"message": "Sesión cerrada"})
        response.delete_cookie(key="session")
        return response

    @app.get("/")
    async def root(request: Request):
        if "user" not in request.session:
            return RedirectResponse("/login")
        return RedirectResponse("/web/index.html")
