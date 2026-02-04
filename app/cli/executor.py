"""
Ejecutor de comandos para la CLI
Ejecuta los comandos parseados y devuelve los resultados
"""

import logging
from typing import Dict
from app.controllers.admin_router import execute_module_action


class CommandExecutor:
    """Ejecuta los comandos parseados de la CLI"""
    
    async def execute(self, parsed_command: Dict) -> str:
        """Ejecuta un comando parseado y devuelve el resultado"""
        try:
            module = parsed_command.get('module')
            action = parsed_command.get('action')
            params = parsed_command.get('params')
            
            if not module or not action:
                return "❌ Comando no soportado"
                
            # Ejecutar usando la función existente de admin_router
            success, message = execute_module_action(
                module_name=module,
                action=action,
                params=params
            )
            
            # Formatear resultado
            if success:
                result = [
                    "",
                    "✅ ÉXITO",
                    "=" * 60,
                    message,
                    "=" * 60,
                ]
            else:
                result = [
                    "",
                    "❌ ERROR",
                    "=" * 60,
                    message,
                    "=" * 60,
                ]
            
            return '\n'.join(result)
        
        except Exception as e:
            logging.error(f"CLI Executor error: {e}")
            return f"❌ Error ejecutando comando: {str(e)}"
