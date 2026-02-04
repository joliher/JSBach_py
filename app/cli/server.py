
"""
Servidor TCP para la CLI de JSBach
Gestiona conexiones entrantes y sesiones CLI
"""

import asyncio
import logging
from typing import Optional

from .session import CLISession


class CLIServer:
    """Servidor TCP para conexiones CLI en el puerto 2200"""
    
    def __init__(self, host: str = "0.0.0.0", port: int = 2200):
        self.host = host
        self.port = port
        self.server: Optional[asyncio.Server] = None
        self.active_sessions = []
        
    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Gestiona una nueva conexión de cliente"""
        addr = writer.get_extra_info('peername')
        logging.info(f"CLI: Nueva conexión desde {addr}")
        
        session = CLISession(reader, writer, addr)
        self.active_sessions.append(session)
        
        try:
            await session.handle()
        except Exception as e:
            logging.error(f"CLI: Error en sesión {addr}: {e}")
        finally:
            self.active_sessions.remove(session)
            logging.info(f"CLI: Conexión cerrada desde {addr}")
    
    async def start(self):
        """Inicia el servidor CLI"""
        self.server = await asyncio.start_server(
            self.handle_client,
            self.host,
            self.port
        )
        
        addr = self.server.sockets[0].getsockname()
        logging.info(f"CLI Server listening on {addr[0]}:{addr[1]}")
        
        async with self.server:
            await self.server.serve_forever()
    
    async def stop(self):
        """Detiene el servidor CLI"""
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            logging.info("CLI Server stopped")
