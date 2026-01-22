"""
Command executor for CLI
Executes parsed commands and returns results
"""

import logging
from typing import Dict

from app.controllers.admin_router import execute_module_action


class CommandExecutor:
    """Executes CLI commands and formats results"""
    
    async def execute(self, parsed_command: Dict) -> str:
        """
        Execute a parsed command
        
        Args:
            parsed_command: Dictionary with command details from parser
            
        Returns:
            Formatted result string
        """
        if parsed_command['command'] != 'module_action':
            return "❌ Comando no soportado"
        
        module = parsed_command['module']
        action = parsed_command['action']
        params = parsed_command.get('params')
        
        try:
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
