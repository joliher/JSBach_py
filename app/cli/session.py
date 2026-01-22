"""
CLI Session handler
Manages individual client connections and command execution
"""

import asyncio
import logging
import os
from typing import Tuple

from app.utils.auth_helper import authenticate_user
from .parser import CommandParser
from .executor import CommandExecutor


class CLISession:
    """Handles a single CLI session for a connected client"""
    
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, addr):
        self.reader = reader
        self.writer = writer
        self.addr = addr
        self.authenticated = False
        self.username = None
        self.role = None
        self.parser = CommandParser()
        self.executor = CommandExecutor()
        
    async def send(self, message: str):
        """Send a message to the client"""
        if not message.endswith('\n'):
            message += '\n'
        self.writer.write(message.encode('utf-8'))
        await self.writer.drain()
    
    async def receive(self) -> str:
        """Receive a line from the client"""
        try:
            data = await asyncio.wait_for(self.reader.readline(), timeout=300.0)
            return data.decode('utf-8').strip()
        except asyncio.TimeoutError:
            return ""
        except Exception as e:
            logging.error(f"CLI: Error receiving data: {e}")
            return ""
    
    async def authenticate(self) -> bool:
        """Authenticate the user"""
        await self.send("=" * 60)
        await self.send("JSBach V4.0 - CLI Management Interface")
        await self.send("=" * 60)
        await self.send("")
        
        # Solicitar credenciales
        await self.send("Username: ")
        username = await self.receive()
        
        if not username:
            return False
        
        await self.send("Password: ")
        password = await self.receive()
        
        if not password:
            return False
        
        # Autenticar contra cli_users.json
        auth_file = os.path.join(os.getcwd(), "config", "cli_users.json")
        success, user_data = authenticate_user(username, password, auth_file)
        
        if success:
            self.authenticated = True
            self.username = username
            self.role = user_data.get("role", "admin")
            await self.send("")
            await self.send(f"✅ Autenticación exitosa. Bienvenido {username}!")
            await self.send("")
            return True
        else:
            await self.send("")
            await self.send("❌ Credenciales incorrectas")
            await self.send("")
            return False
    
    async def show_prompt(self):
        """Display the command prompt"""
        prompt = f"jsbach@{self.username}> "
        self.writer.write(prompt.encode('utf-8'))
        await self.writer.drain()
    
    async def handle(self):
        """Main session handler"""
        try:
            # Autenticación
            if not await self.authenticate():
                await self.send("Conexión cerrada.")
                self.writer.close()
                await self.writer.wait_closed()
                return
            
            # Mostrar ayuda inicial
            await self.send("Escribe 'help' para ver los comandos disponibles.")
            await self.send("Escribe 'exit' o 'quit' para salir.")
            await self.send("")
            
            # Loop de comandos
            while True:
                await self.show_prompt()
                command = await self.receive()
                
                if not command:
                    continue
                
                # Comandos especiales
                if command.lower() in ['exit', 'quit', 'logout']:
                    await self.send("")
                    await self.send("👋 Cerrando sesión...")
                    break
                
                # Parsear y ejecutar comando
                try:
                    parsed = self.parser.parse(command)
                    
                    if parsed['command'] == 'help':
                        help_text = self.parser.get_help(parsed.get('args', []))
                        await self.send(help_text)
                    else:
                        result = await self.executor.execute(parsed)
                        await self.send(result)
                    
                except Exception as e:
                    await self.send(f"❌ Error: {str(e)}")
                
                await self.send("")
        
        except Exception as e:
            logging.error(f"CLI Session error: {e}")
        
        finally:
            self.writer.close()
            await self.writer.wait_closed()
