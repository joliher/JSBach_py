
"""
Parser de comandos para la CLI
Parsea la entrada del usuario y valida los comandos
"""

import os
import re
from typing import Dict, List


class CommandParser:
    """Parsea y valida los comandos de la CLI"""
    
    # Módulos disponibles
    MODULES = ['wan', 'nat', 'firewall', 'dmz', 'vlans', 'tagging', 'ebtables']
    
    # Acciones comunes
    COMMON_ACTIONS = ['start', 'stop', 'restart', 'status', 'config']
    
    # Acciones específicas por módulo
    MODULE_ACTIONS = {
        'firewall': ['enable_whitelist', 'disable_whitelist', 'add_rule', 'remove_rule', 'aislar', 'desaislar', 'restrict', 'unrestrict'],
        'dmz': ['add_destination', 'remove_destination', 'isolate_dmz_host', 'unisolate_dmz_host', 'aislar', 'desaislar', 'eliminar'],
    }
    
    def parse(self, command_line: str) -> Dict:
        """
        Parsea una línea de comando en sus componentes
        Formato: <módulo> <acción> [--clave valor ...]
        Ejemplos:
            wan status
            nat start
            firewall add_rule --vlan_id 1 --target ACCEPT
            ebtables add_mac --mac AA:BB:CC:DD:EE:FF
            dmz add_destination --ip 10.0.2.5 --port 80
        """
        if not command_line.strip():
            raise ValueError("Comando vacío")
        
        parts = command_line.strip().split()
        
        if len(parts) < 1:
            raise ValueError("Comando inválido")
        
        # Comando help o ?
        if parts[0].lower() in ('help', '?'):
            return {
                'command': 'help',
                'args': parts[1:] if len(parts) > 1 else []
            }

        # Si el primer token no es un módulo válido, comando no válido
        if parts[0].lower() not in self.MODULES:
            return "comando no válido"
        
        # Comandos de módulo
        if len(parts) < 2:
            return self._invalid_command_message(parts[0] if parts else None)

        module = parts[0].lower()
        action = parts[1].lower()
        params = {}
        param_parts = parts[2:]
        i = 0
        while i < len(param_parts):
            part = param_parts[i]
            if not part.startswith('--'):
                raise ValueError(f"Parámetro inválido: {part}\nUse formato: --key value")
            key = part[2:]
            if i + 1 < len(param_parts) and not param_parts[i + 1].startswith('--'):
                value = param_parts[i + 1]
                try:
                    if '.' in value:
                        value = float(value)
                    else:
                        value = int(value)
                except ValueError:
                    pass
                params[key] = value
                i += 2
            else:
                params[key] = True
                i += 1
        return {
            'command': 'module_action',
            'module': module,
            'action': action,
            'params': params
        }

    # --- AYUDA DE MÓDULO O ACCIÓN ---
    def get_help(self, args: List[str]) -> str:
        """Genera el texto de ayuda para la CLI"""
        if not args:
            # Ayuda general: solo módulos y cómo pedir ayuda de un módulo
            help_text = [
                "",
                "=" * 60,
                "JSBACH V4.0 - AYUDA GENERAL",
                "=" * 60,
                "",
                "MÓDULOS DISPONIBLES:",
            ]
            for module in self.MODULES:
                help_text.append(f"  • {module}")
            help_text.extend([
                "",
                "Para ver los comandos de un módulo:",
                "  help <módulo>",
                "",
                "Ejemplo:",
                "  help wan",
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
            # Ayuda de un módulo o acción específica
            module = args[0].lower()
            if module not in self.MODULES:
                return f"❌ Módulo desconocido: {module}"

            help_file = os.path.join(
                os.path.dirname(__file__),
                'help',
                f'{module}.md'
            )
            if os.path.exists(help_file):
                try:
                    with open(help_file, 'r', encoding='utf-8') as f:
                        md = f.read()
                    # Si piden ayuda extendida: help <módulo> <acción>
                    if len(args) > 1:
                        action = args[1].lower()
                        # Solo permitir ayuda extendida para acciones comunes
                        if action in self.COMMON_ACTIONS:
                            pat = re.compile(r'^(#+)\s+.*' + re.escape(action) + r'.*$', re.IGNORECASE | re.MULTILINE)
                            matches = list(pat.finditer(md))
                            if matches:
                                start = matches[0].start()
                                next_header = re.search(r'^#{2,}\s', md[start+1:], re.MULTILINE)
                                end = start + 1 + next_header.start() if next_header else len(md)
                                section = md[start:end].strip()
                                # Resaltar parámetros --param en verde
                                GREEN = "\033[92m"
                                RESET = "\033[0m"
                                section = re.sub(r'(\s|^)(--[\w-]+)', r'\1' + GREEN + r'\2' + RESET, section)
                                return section
                            # Si no hay sección, fallback a ayuda de módulo
                    # Resaltar parámetros --param y nombres de parámetros de sección en verde en todo el md
                    GREEN = "\033[92m"
                    RESET = "\033[0m"
                    # --param
                    md_colored = re.sub(r'(\s|^)(--[\w-]+)', r'\1' + GREEN + r'\2' + RESET, md)
                    # Nombres de parámetros de sección (### param o   - param:)
                    md_colored = re.sub(r'^(###\s*)([\w-]+)', r'\1' + GREEN + r'\2' + RESET, md_colored, flags=re.MULTILINE)
                    md_colored = re.sub(r'(\n\s*-\s*)([\w-]+)(:)', r'\1' + GREEN + r'\2' + RESET + r'\3', md_colored)
                    return md_colored
                except Exception:
                    pass

            # Ayuda básica si no hay archivo
            help_text = [
                f"Uso: {module} <acción> [opciones]",
                f"",
                f"Módulo: {module}",
                f"",
                f"Acciones disponibles:",
            ]
            GREEN = "\033[92m"
            RESET = "\033[0m"
            for action in self.COMMON_ACTIONS:
                help_text.append(f"  {GREEN}{action}{RESET}")
            if module in self.MODULE_ACTIONS:
                for action in self.MODULE_ACTIONS[module]:
                    help_text.append(f"  {GREEN}{action}{RESET}")
            help_text.append("")
            help_text.append("Opciones: Usa --key value según la acción.")
            help_text.append("")
            help_text.append("Ejemplos:")
            help_text.append(f"  {module} status")
            help_text.append(f"  {module} start")
            help_text.append(f"  {module} stop")
            help_text.append("")
            help_text.append(f"Para más detalles, usa 'help {module}' o consulta la documentación.")
            return '\n'.join(help_text)
        
        # Soporte legacy: JSON directo
        if full_str.strip().startswith('{'):
            import json
            try:
                return json.loads(full_str)
            except json.JSONDecodeError:
                # Si no es JSON válido, procesar como flags
                pass
        
        # Procesar como flags modernos: --key value
        params = {}
        i = 0
        while i < len(param_parts):
            part = param_parts[i]
            
            # Debe comenzar con --
            if not part.startswith('--'):
                raise ValueError(f"Parámetro inválido: {part}\nUse formato: --key value")
            
            # Extraer nombre del flag (sin --)
            key = part[2:]
            
            # Verificar si tiene valor o es flag booleano
            if i + 1 < len(param_parts) and not param_parts[i + 1].startswith('--'):
                # Tiene valor
                value = param_parts[i + 1]
                
                # Intentar convertir a número si es posible
                try:
                    if '.' in value:
                        value = float(value)
                    else:
                        value = int(value)
                except ValueError:
                    # Mantener como string
                    pass
                
                params[key] = value
                i += 2
            else:
                # Flag booleano (sin valor)
                params[key] = True
                i += 1
        
        return params if params else None
    
    def get_help(self, args: List[str]) -> str:
        """Generate help text"""
        if not args:
            # Ayuda general: solo módulos y cómo pedir ayuda de un módulo
            help_text = [
                "",
                "=" * 60,
                "JSBACH V4.0 - AYUDA GENERAL",
                "=" * 60,
                "",
                "MÓDULOS DISPONIBLES:",
            ]
            for module in self.MODULES:
                help_text.append(f"  • {module}")
            help_text.extend([
                "",
                "Para ver los comandos de un módulo:",
                "  help <módulo>",
                "",
                "Ejemplo:",
                "  help wan",
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
                except Exception:
                    pass

            # Ayuda básica estilo bash
            help_text = [
                f"Usage: {module} <acción> [opciones]",
                f"",
                f"Módulo: {module}",
                f"",
                f"Acciones disponibles:",
            ]
            for action in self.COMMON_ACTIONS:
                help_text.append(f"  {action}")
            if module in self.MODULE_ACTIONS:
                for action in self.MODULE_ACTIONS[module]:
                    help_text.append(f"  {action}")
            help_text.append("")
            help_text.append("Opciones: Usa --key value según la acción.")
            help_text.append("")
            help_text.append("Ejemplos:")
            help_text.append(f"  {module} status")
            help_text.append(f"  {module} start")
            help_text.append(f"  {module} stop")
            help_text.append("")
            help_text.append("Para más detalles, usa 'help {module}' o consulta la documentación.")
            return '\n'.join(help_text)
