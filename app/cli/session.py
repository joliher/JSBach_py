"""
Manejador de sesión CLI de JSBach
Gestiona conexiones de clientes y ejecución de comandos
"""
import asyncio
import logging
import os
from typing import Tuple

from app.utils.auth_helper import authenticate_user
from .parser import CommandParser
from .executor import CommandExecutor

class CLISession:
    """Gestiona una única sesión CLI para un cliente conectado"""
    
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, addr: Tuple):
        self.reader = reader
        self.writer = writer
        self.addr = addr
        self.authenticated = False
        self.username = ""
        self.role = ""
        self.parser = CommandParser()
        self.executor = CommandExecutor()

    async def send(self, message: str):
        """Enviar un mensaje al cliente"""
        if not message.endswith('\n'):
            message += '\n'
        self.writer.write(message.encode('utf-8'))
        await self.writer.drain()

    async def receive(self, mask_input: bool = False) -> str:
        """Recibe una línea del cliente. Si mask_input es True, muestra * en vez de los caracteres reales (para contraseña)."""
        if not mask_input:
            try:
                line = await asyncio.wait_for(self.reader.readline(), timeout=300.0)
                if not line:
                    return ""
                return line.decode('utf-8').strip()
            except asyncio.TimeoutError:
                return ""
            except Exception as e:
                logging.error(f"CLI: Error receiving data: {e}")
                return ""
        else:
            # Modo oculto: leer carácter a carácter y mostrar *
            password = ""
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
                            password = password[:-1]
                            await self.send('\b \b')
                        continue
                    password += c
                    # Enviar * al cliente
                    self.writer.write(b'*')
                    await self.writer.drain()
                await self.send('')  # Nueva línea
                return password.strip()
            except Exception as e:
                logging.error(f"CLI: Error receiving masked input: {e}")
                return ""

    async def authenticate(self) -> bool:
        """Autentica al usuario"""
        await self.send("=" * 60)
        await self.send("JSBach V4.0 - CLI Management Interface")
        await self.send("=" * 60)
        await self.send("")
        
        await self.send("Username: ")
        username = await self.receive()
        if not username:
            return False
            
        await self.send("Password: ")
        password = await self.receive(mask_input=True)
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
        """Muestra el prompt de comandos"""
        prompt = f"jsbach@{self.username}> "
        self.writer.write(prompt.encode('utf-8'))
        await self.writer.drain()

    async def handle(self):
        """Manejador principal de la sesión CLI"""
        try:
            # Autenticación
            if not await self.authenticate():
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
                    break
                
                # Comandos especiales
                if command.lower() in ['exit', 'quit', 'logout']:
                    await self.send("\n👋 Cerrando sesión...")
                    break
                
                # Parsear y ejecutar comando
                try:
                    parsed = self.parser.parse(command)
                    
                    if isinstance(parsed, str):
                        await self.send(parsed)
                    elif parsed.get('command') == 'help':
                        help_text = self.parser.get_help(parsed.get('args', []))
                        await self.send(help_text)
                    elif parsed.get('command') == 'module_action':
                        result = await self.executor.execute(parsed)
                        await self.send(result)
                    else:
                        await self.send("❌ Comando no reconocido")
                        
                except Exception as e:
                    await self.send(f"❌ Error: {str(e)}")
                
                await self.send("")
        
        except Exception as e:
            logging.error(f"CLI Session error: {e}")
        
        finally:
            self.writer.close()
            await self.writer.wait_closed()
