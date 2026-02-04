import os
import asyncio
import logging
from app.cli import CLIServer

if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    logging.basicConfig(level=logging.INFO)
    cli_server = CLIServer(host="0.0.0.0", port=2200)
    try:
        asyncio.run(cli_server.start())
    except KeyboardInterrupt:
        print("\nCLI server stopped.")
