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

"""
Manejador de sesión CLI
Gestiona conexiones de clientes y ejecución de comandos
"""
    """Handles a single CLI session for a connected client"""
import asyncio
import logging
import os
        self.addr = addr
from app.utils.auth_helper import authenticate_user
from .parser import CommandParser
from .executor import CommandExecutor
        self.parser = CommandParser()
        self.executor = CommandExecutor()
class CLISession:
    """Gestiona una única sesión CLI para un cliente conectado"""
        """Send a message to the client"""
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, addr):
            message += '\n'
        self.writer.write(message.encode('utf-8'))
        await self.writer.drain()
    

    async def receive(self, mask_input: bool = False) -> str:
        """Receive a line from the client. If mask_input is True, echo * instead of real chars (for password)."""
        if not mask_input:
            try:
    async def send(self, message: str):
        """Enviar un mensaje al cliente"""
            except asyncio.TimeoutError:
                return ""
            except Exception as e:
                logging.error(f"CLI: Error receiving data: {e}")
                return ""
        else:
    async def receive(self, mask_input: bool = False) -> str:
        """Recibe una línea del cliente. Si mask_input es True, muestra * en vez de los caracteres reales (para contraseña)."""
            try:
                while True:
                    char = await asyncio.wait_for(self.reader.read(1), timeout=300.0)
                    if not char:
                        break
                    c = char.decode('utf-8', errors='ignore')
                    if c in ('\n', '\r'):
                        break
                    if c == '\x7f':  # Backspace
                        if password:
            # Modo oculto: leer carácter a carácter y mostrar *
                            await self.send('\b \b')
                        continue
                    password += c
                    await self.send('*',)
                await self.send('')  # Nueva línea
                return password.strip()
            except Exception as e:
                logging.error(f"CLI: Error receiving masked input: {e}")
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
    async def authenticate(self) -> bool:
        """Autentica al usuario"""
        await self.send("Password: ")
        password = await self.receive(mask_input=True)
        if not password:
            return False
        
        # Solicitar credenciales
        auth_file = os.path.join(os.getcwd(), "config", "cli_users.json")
        success, user_data = authenticate_user(username, password, auth_file)
        
        if success:
            self.authenticated = True
            self.username = username
            self.role = user_data.get("role", "admin")
            await self.send("")
            await self.send(f"✅ Autenticación exitosa. Bienvenido {username}!")
            await self.send("")
        # Autenticar contra cli_users.json
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
    async def show_prompt(self):
        """Muestra el prompt de comandos"""
                await self.writer.wait_closed()
                return
            
            # Mostrar ayuda inicial
    async def handle(self):
        """Manejador principal de la sesión CLI"""
            await self.send("")
            # Autenticación
            # Loop de comandos
            while True:
                await self.show_prompt()
                command = await self.receive()
                
                if not command:
            # Mostrar ayuda inicial
                
                # Comandos especiales
                if command.lower() in ['exit', 'quit', 'logout']:
                    await self.send("")
            # Bucle principal de comandos
                    break
                
                # Parsear y ejecutar comando
                try:
                    parsed = self.parser.parse(command)
                    if isinstance(parsed, str):
                        await self.send(parsed)
                # Comandos especiales
                        help_text = self.parser.get_help(parsed.get('args', []))
                        BLUE = "\033[94m"
                        RESET = "\033[0m"
                        colored_help = f"{BLUE}{help_text}{RESET}"
                        await self.send(colored_help)
                # Parsear y ejecutar comando
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
