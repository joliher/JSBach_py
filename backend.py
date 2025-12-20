from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
import subprocess
import os

# Necesario para que Uvicorn se inicie
app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")
SCRIPTS_DIR = os.path.join(BASE_DIR, "scripts")

ALLOWED_SCRIPTS = {
    "test.py"
}
SCRIPT_TIMEOUT = 5

# Comprueba si el path (endpoint) que se le pasa existe y es .py
def script_path(name: str) -> str:
    if name not in ALLOWED_SCRIPTS:
        raise HTTPException(
            status_code=403,
            detail="Script no permitido"
        )

    path = os.path.join(SCRIPTS_DIR, name)
    
    if not os.path.isfile(path):
        raise HTTPException(
            status_code=404,
            detail="Script no encontrado"
        )
    return path

# Cuando se matchee con /
@app.get("/")
def root():
    index_path = os.path.join(STATIC_DIR, "index.html")
    if not os.path.isfile(index_path):
        raise HTTPException(status_code=404, detail="index.html no encontrado")
    return FileResponse(index_path)

# Cuando matchee con /run/<script>.py
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
        raise HTTPException(
            status_code=408,
            detail="El script excedió el tiempo máximo de ejecución"
        )

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error ejecutando el script: {str(e)}"
        )
    
    return JSONResponse(
        {
            "script": script_name,
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr
        }
    )
    
################
# SERVIR  JSON #
################
# return {
#            "script": script_name,
#            "returncode": result.returncode,
#            "stdout": result.stdout,
#            "stderr": result.stderr
#        }

