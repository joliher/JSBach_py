"""
TCP Server for JSBach CLI
Handles incoming connections and manages CLI sessions
"""

import asyncio
import logging
from typing import Optional

from .session import CLISession


class CLIServer:
    """TCP server for CLI connections on port 2200"""
    
    def __init__(self, host: str = "0.0.0.0", port: int = 2200):
        self.host = host
        self.port = port
        self.server: Optional[asyncio.Server] = None
        self.active_sessions = []
        
    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle a new client connection"""
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
        """Start the CLI server"""
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
        """Stop the CLI server"""
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            logging.info("CLI Server stopped")
