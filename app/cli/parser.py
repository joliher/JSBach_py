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
    MODULES = ['wan', 'nat', 'firewall', 'dmz', 'vlans', 'tagging', 'ebtables', 'expect']
    
    # Acciones comunes
    COMMON_ACTIONS = ['start', 'stop', 'restart', 'status', 'config']
    
    # Acciones específicas por módulo
    MODULE_ACTIONS = {
        'firewall': ['enable_whitelist', 'disable_whitelist', 'add_rule', 'remove_rule', 'aislar', 'desaislar', 'restrict', 'unrestrict'],
        'dmz': ['add_destination', 'remove_destination', 'isolate_dmz_host', 'unisolate_dmz_host', 'aislar', 'desaislar', 'eliminar'],
        'expect': ['auth', 'profile-mod', 'reset', 'port-security'],
    }
    
    def parse(self, command_line: str) -> Dict:
        """
        Parsea una línea de comando en sus componentes
        Formato: <módulo> <acción> [--clave valor ...]
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
            return f"❌ Uso: {parts[0].lower()} <acción> [parámetros]"

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

    def _apply_colors(self, text: str) -> str:
        """
        Aplica colores ANSI al texto de ayuda.
        Base: Azul (\033[94m)
        Resaltado: Verde (\033[92m)
        Valores Variables: Blanco (\033[0m)
        """
        GREEN = "\033[92m"
        BLUE = "\033[94m"
        WHITE = "\033[0m"
        RESET = "\033[0m"
        
        lines = text.split('\n')
        colored_lines = []
        modules_pat = '|'.join(self.MODULES)
        
        for line in lines:
            # 1. Detectar si es una línea de ejemplo de comando
            # Formato: [espacios][módulo] [acción] [parámetros...]
            match_example = re.match(r'^(\s{2})(' + modules_pat + r')\s+([\w-]+)(.*)$', line)
            
            if match_example:
                indent = match_example.group(1)
                module = match_example.group(2)
                action = match_example.group(3)
                rest = match_example.group(4)
                
                # Módulo y acción en verde, seguido de reset a blanco para los valores
                colored_line = f"{BLUE}{indent}{GREEN}{module} {action}{WHITE}"
                
                # Procesar el resto (flags y valores)
                # Queremos --flag en verde y su valor en blanco
                parts = re.split(r'(--[\w-]+)', rest)
                for part in parts:
                    if not part:
                        continue
                    if part.startswith('--'):
                        colored_line += f"{GREEN}{part}{WHITE}"
                    else:
                        # Espacios y valores se quedan en blanco (ya seteado por el anterior o por el inicio)
                        colored_line += part
                
                colored_lines.append(colored_line)
                continue

            # 2. Detectar headers (### acción)
            if line.strip().startswith('###'):
                # Header estilo "### module action"
                match_header = re.match(r'^(\s*###\s+)([\w-]+)\s+([\w-]+)(.*)', line)
                if match_header:
                    colored_lines.append(f"{BLUE}{match_header.group(1)}{GREEN}{match_header.group(2)} {match_header.group(3)}{BLUE}{match_header.group(4)}")
                else:
                    # Header genérico "### titulo"
                    colored_lines.append(re.sub(r'^(###\s*)([\w-]+)', r'\1' + GREEN + r'\2' + BLUE, line))
                continue

            # 3. Detectar listado de parámetros (- --param:)
            if '--' in line and (line.strip().startswith('-') or line.strip().startswith('•')):
                # Resaltar solo el flag en verde
                colored_line = re.sub(r'(--[\w-]+)', GREEN + r'\1' + BLUE, line)
                colored_lines.append(BLUE + colored_line)
                continue

            # 4. Texto normal en azul
            colored_lines.append(BLUE + line)
                
        return '\n'.join(colored_lines) + RESET

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
                "Para ver ayuda de una acción específica:",
                "  help <módulo> <acción>",
                "",
                "Ejemplos:",
                "  help wan",
                "  help firewall add_rule",
                "",
                "COMANDOS ESPECIALES:",
                "  • help       - Mostrar esta ayuda",
                "  • exit/quit  - Cerrar sesión",
                "",
                "=" * 60,
                ""
            ])
            # La ayuda general también se colorea
            return self._apply_colors('\n'.join(help_text))
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
                        
                        # Buscar sección para CUALQUIER acción (no solo comunes)
                        pat = re.compile(r'^(#+)\s+.*' + re.escape(action) + r'.*$', re.IGNORECASE | re.MULTILINE)
                        matches = list(pat.finditer(md))
                        
                        if matches:
                            # Sección encontrada - extraer contenido
                            start = matches[0].start()
                            match_end = matches[0].end()
                            next_header = re.search(r'^#{2,}\s', md[match_end:], re.MULTILINE)
                            end = match_end + next_header.start() if next_header else len(md)
                            section = md[start:end].strip()
                            
                            return self._apply_colors(section)
                        else:
                            # Sección NO encontrada - mensaje informativo
                            YELLOW = "\033[93m"
                            RESET = "\033[0m"
                            
                            # Verificar si la acción existe en el módulo
                            action_exists = action in self.COMMON_ACTIONS
                            if module in self.MODULE_ACTIONS:
                                if action in self.MODULE_ACTIONS[module]:
                                    action_exists = True
                            
                            if action_exists:
                                warning = f"{YELLOW}⚠️  No se encontró documentación específica para '{action}' en el archivo de ayuda.{RESET}\n\n"
                                warning += f"La acción '{action}' existe pero no tiene una sección dedicada.\n"
                                warning += f"Mostrando ayuda completa del módulo '{module}':\n\n"
                                warning += "=" * 60 + "\n\n"
                            else:
                                warning = f"{YELLOW}⚠️  La acción '{action}' no existe en el módulo '{module}'.{RESET}\n\n"
                                warning += f"Mostrando ayuda completa del módulo para ver las acciones disponibles:\n\n"
                                warning += "=" * 60 + "\n\n"
                            
                            return warning + self._apply_colors(md)
                    
                    # Ayuda completa del módulo (sin acción específica)
                    return self._apply_colors(md)
                    
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
            help_text.append(f"Para más detalles, usa 'help {module}' o consulta la documentación.")
            return self._apply_colors('\n'.join(help_text))
