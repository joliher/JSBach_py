"""
Command parser for CLI
Parses user input and validates commands
"""

import os
from typing import Dict, List, Optional


class CommandParser:
    """Parses and validates CLI commands"""
    
    # Módulos disponibles
    MODULES = ['wan', 'nat', 'firewall', 'dmz', 'vlans', 'tagging']
    
    # Acciones comunes
    COMMON_ACTIONS = ['start', 'stop', 'restart', 'status', 'config']
    
    # Acciones específicas por módulo
    MODULE_ACTIONS = {
        'firewall': ['enable_whitelist', 'disable_whitelist', 'add_rule', 'remove_rule', 'aislar', 'desaislar', 'restrict', 'unrestrict'],
        'dmz': ['add_destination', 'remove_destination', 'isolate_dmz_host', 'unisolate_dmz_host', 'aislar', 'desaislar', 'eliminar'],
    }
    
    def parse(self, command_line: str) -> Dict:
        """
        Parse a command line into components
        
        Format: <module> <action> [params]
        Examples:
            wan status
            nat start
            firewall add_rule --params '{"rule": "..."}'
        """
        if not command_line.strip():
            raise ValueError("Comando vacío")
        
        parts = command_line.strip().split()
        
        if len(parts) < 1:
            raise ValueError("Comando inválido")
        
        # Comando help
        if parts[0].lower() == 'help':
            return {
                'command': 'help',
                'args': parts[1:] if len(parts) > 1 else []
            }
        
        # Comandos de módulo
        if len(parts) < 2:
            raise ValueError(f"Uso: <módulo> <acción> [parámetros]\nEjemplo: {parts[0]} status")
        
        module = parts[0].lower()
        action = parts[1].lower()
        
        # Validar módulo
        if module not in self.MODULES:
            raise ValueError(f"Módulo desconocido: {module}\nMódulos disponibles: {', '.join(self.MODULES)}")
        
        # Parsear parámetros (si existen)
        params = None
        if len(parts) > 2:
            # Si hay --params, usar esa sintaxis
            if '--params' in parts:
                idx = parts.index('--params')
                if idx + 1 < len(parts):
                    import json
                    try:
                        params = json.loads(' '.join(parts[idx+1:]))
                    except json.JSONDecodeError as e:
                        raise ValueError(f"Error en formato JSON: {e}")
            else:
                # Asumir que lo que sigue a la acción es JSON directo
                import json
                json_str = ' '.join(parts[2:])
                try:
                    params = json.loads(json_str)
                except json.JSONDecodeError as e:
                    # Si no es JSON válido, ignorar
                    pass
        
        return {
            'command': 'module_action',
            'module': module,
            'action': action,
            'params': params
        }
    
    def get_help(self, args: List[str]) -> str:
        """Generate help text"""
        if not args:
            # Ayuda general - intentar cargar CLI_COMMANDS.md
            help_file = os.path.join(
                os.path.dirname(__file__),
                'help',
                'CLI_COMMANDS.md'
            )
            
            if os.path.exists(help_file):
                try:
                    with open(help_file, 'r', encoding='utf-8') as f:
                        return f.read()
                except Exception as e:
                    pass  # Si falla, usar ayuda básica
            
            # Ayuda general básica (fallback)
            help_text = [
                "",
                "=" * 60,
                "JSBACH V4.0 - COMANDOS DISPONIBLES",
                "=" * 60,
                "",
                "FORMATO:",
                "  <módulo> <acción> [--params '{json}']",
                "",
                "MÓDULOS DISPONIBLES:",
            ]
            for module in self.MODULES:
                help_text.append(f"  • {module}")
            
            help_text.extend([
                "",
                "ACCIONES COMUNES:",
                "  • start      - Iniciar el módulo",
                "  • stop       - Detener el módulo",
                "  • restart    - Reiniciar el módulo",
                "  • status     - Ver estado del módulo",
                "  • config     - Configurar el módulo",
                "",
                "EJEMPLOS:",
                "  wan status",
                "  nat start",
                "  firewall stop",
                "  dmz status",
                "",
                "Para ayuda específica de un módulo:",
                "  help <módulo>",
                "",
                "COMANDOS ESPECIALES:",
                "  • help       - Mostrar esta ayuda",
                "  • exit/quit  - Cerrar sesión",
                "",
                "=" * 60,
                ""
            ])
            
            return '\n'.join(help_text)
        
        else:
            # Ayuda de un módulo específico
            module = args[0].lower()
            
            if module not in self.MODULES:
                return f"❌ Módulo desconocido: {module}"
            
            # Intentar cargar archivo de ayuda del módulo
            help_file = os.path.join(
                os.path.dirname(__file__),
                'help',
                f'{module}.md'
            )
            
            if os.path.exists(help_file):
                try:
                    with open(help_file, 'r', encoding='utf-8') as f:
                        return f.read()
                except Exception as e:
                    # Si falla, usar ayuda básica
                    pass
            
            # Ayuda básica si no hay archivo
            help_text = [
                "",
                f"=" * 60,
                f"MÓDULO: {module.upper()}",
                f"=" * 60,
                "",
                "ACCIONES DISPONIBLES:",
            ]
            
            # Acciones comunes
            for action in self.COMMON_ACTIONS:
                help_text.append(f"  • {action}")
            
            # Acciones específicas
            if module in self.MODULE_ACTIONS:
                help_text.append("")
                help_text.append("ACCIONES ESPECÍFICAS:")
                for action in self.MODULE_ACTIONS[module]:
                    help_text.append(f"  • {action}")
            
            help_text.extend([
                "",
                "EJEMPLOS:",
                f"  {module} status",
                f"  {module} start",
                f"  {module} stop",
                "",
                "=" * 60,
                ""
            ])
            
            return '\n'.join(help_text)
