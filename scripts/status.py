import json
import os

# Lista blanca de archivos JSON (solo nombres, sin ruta)
white_list = [
    "wan.json",
    "nat.json",
    "bridge/vlans.json",
    "bridge/bridge.json"
]

# Ruta base donde se encuentran los archivos
BASE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "config"
)

def estado_to_text(estado):
    """Convierte el estado numérico a texto."""
    if estado == 1:
        return "ACTIVO"
    elif estado == 0:
        return "INACTIVO"
    else:
        return "DESCONOCIDO"

def main():
    for archivo in white_list:
        ruta_completa = os.path.join(BASE_PATH, archivo)

        if not os.path.isfile(ruta_completa):
            print(f"{ruta_completa} | NO ENCONTRADO")
            continue

        try:
            with open(ruta_completa, 'r', encoding='utf-8') as f:
                data = json.load(f)

            estado = data.get("status", -1)
            print(f"{ruta_completa} | {estado_to_text(estado)}")

        except json.JSONDecodeError:
            print(f"{ruta_completa} | JSON INVÁLIDO")
        except Exception as e:
            print(f"{ruta_completa} | ERROR: {e}")

if __name__ == "__main__":
    main()