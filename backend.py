from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, FileResponse
import subprocess
import os

# Necesario para que Uvicorn se inicie
app = FastAPI()

STATIC_DIR = "static"
SCRIPTS_DIR = "scripts"

# Comprueba si el path (endpoint) que se le pasa existe y es .py
def script_path(name: str) -> str:
    path = os.path.join(SCRIPTS_DIR, name)
    if not path.endswith(".py"):
        raise HTTPException(status_code=400, detail="Script inválido")
    if not os.path.isfile(path):
        raise HTTPException(status_code=404, detail="Script no encontrado")
    return path

# Cuando se matchee con /
@app.get("/")
def root():
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))

# Cuando matchee con /run/<script>.py
@app.get("/run/{script_name}")
def run_script(script_name: str):
    path = script_path(script_name)

    result = subprocess.run(
        ["python3", path],
        capture_output=True,
        text=True
    )
    
    html_name = os.path.splitext(script_name)[0] + ".html"
    html_path = os.path.join(STATIC_DIR, html_name)

    # Comprueba si el HTML existe
    if not os.path.isfile(html_path):
        raise HTTPException(status_code=404, detail=f"{html_name} no encontrado")

    return FileResponse(html_path)

################
# SERVIR  JSON #
################
# return {
#            "script": script_name,
#            "returncode": result.returncode,
#            "stdout": result.stdout,
#            "stderr": result.stderr
#        }

