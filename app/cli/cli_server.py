
"""
Script de arranque para el servidor CLI de JSBach
"""

import os
import sys
import asyncio
import logging

# Añade la raíz del proyecto al sys.path
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from app.cli import CLIServer

if __name__ == "__main__":
    os.chdir(ROOT)
    logging.basicConfig(level=logging.INFO)
    cli_server = CLIServer(host="0.0.0.0", port=2200)
    try:
        asyncio.run(cli_server.start())
    except KeyboardInterrupt:
        print("\nServidor CLI detenido.")
