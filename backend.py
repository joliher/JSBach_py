from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
import subprocess
import os

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")
SCRIPTS_DIR = os.path.join(BASE_DIR, "scripts")

# Carpeta de funciones
FUNCIONES = ["wan", "nat", "bridge", "firewall"]

# Montamos cada carpeta de función como StaticFiles
for func in FUNCIONES:
    func_dir = os.path.join(STATIC_DIR, func)
    if os.path.isdir(func_dir):
        app.mount(f"/{func}", StaticFiles(directory=func_dir, html=True), name=func)

# Archivos estáticos de raíz permitidos
ALLOWED_STATIC = {"header.html", "status.html", "info.html"}

# Scripts permitidos
ALLOWED_SCRIPTS = {"test.py"}
SCRIPT_TIMEOUT = 5

# Ejecutar script
def script_path(name: str) -> str:
    if name not in ALLOWED_SCRIPTS:
        raise HTTPException(status_code=403, detail="Script no permitido")
    path = os.path.join(SCRIPTS_DIR, name)
    if not os.path.isfile(path):
        raise HTTPException(status_code=404, detail="Script no encontrado")
    return path

@app.get("/run/{script_name}")
def run_script(script_name: str):
    path = script_path(script_name)
    try:
        result = subprocess.run(
            ["python3", path],
            capture_output=True,
            text=True,
            timeout=SCRIPT_TIMEOUT
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=408, detail="El script excedió el tiempo máximo de ejecución")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error ejecutando el script: {str(e)}")
    return JSONResponse({
        "script": script_name,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr
    })

# Servir archivos de raíz
@app.get("/{file_name}")
def serve_file(file_name: str):
    if file_name not in ALLOWED_STATIC:
        raise HTTPException(status_code=404, detail="Archivo no permitido")
    path = os.path.join(STATIC_DIR, file_name)
    if os.path.isfile(path):
        return FileResponse(path)
    raise HTTPException(status_code=404, detail="Archivo no encontrado")

# Servir index principal
@app.get("/")
def root():
    index_path = os.path.join(STATIC_DIR, "index.html")
    if os.path.isfile(index_path):
        return FileResponse(index_path)
    raise HTTPException(status_code=404, detail="index.html no encontrado")
