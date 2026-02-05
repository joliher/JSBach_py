#!/usr/bin/env python3
"""
Test suite COMPLETO para JSBach V4.0 - Refactorización Fases 1-4
===============================================================================
Incluye pruebas de:
1. Happy path (funcionalidad normal)
2. Error handling (validaciones)
3. Edge cases (casos límite)

Módulos validados:
- wan: status, validación de parámetros
- vlans: start/stop, config show, validación de IDs
- firewall: whitelist, aislar, restrict, validación de parámetros
- dmz: add_destination, aislar, validación de IPs/puertos
- ebtables: aislar, desaislar, MAC whitelist, validación de VLANs
===============================================================================
"""

import sys
import os
import time


# Compatibilidad para ejecución directa: python3 <archivo>.py
try:
    from app.controllers.admin_router import execute_module_action
except ModuleNotFoundError:
    # Añadir el directorio raíz del proyecto al sys.path si no se encuentra el módulo
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.abspath(os.path.join(current_dir, '..'))
    if project_root not in sys.path:
        sys.path.insert(0, project_root)
    try:
        from app.controllers.admin_router import execute_module_action
    except ModuleNotFoundError as e:
        print(f"[ERROR] No se pudo importar execute_module_action: {e}")
        print(f"Asegúrate de ejecutar el test desde la raíz del proyecto JSBach_V4.0")
        sys.exit(1)


class ComprehensiveTestRunner:
    """Test runner más completo con validaciones"""
    
    def __init__(self):
        self.results = {}
        self.total = 0
        self.passed = 0
    
    def test(self, module: str, test_name: str, action: str, params: dict, expect_success: bool = True, count_as_test: bool = True):
        """Ejecutar un test y registrar resultado"""
        if count_as_test:
            self.total += 1
        
        try:
            success, message = execute_module_action(
                module_name=module,
                action=action,
                params=params
            )
            
            # Si no cuenta como test, solo ejecutar sin validar
            if not count_as_test:
                return
            
            # Validar resultado
            if expect_success and success:
                result = "✅ PASS"
                self.passed += 1
            elif not expect_success and not success:
                result = "✅ PASS (error esperado)"
                self.passed += 1
            else:
                result = "❌ FAIL"
                if expect_success:
                    print(f"    ❌ Se esperaba éxito pero falló: {message[:80]}")
                else:
                    print(f"    ❌ Se esperaba error pero tuvo éxito: {message[:80]}")
        
        except Exception as e:
            result = "❌ FAIL (excepción)"
            print(f"    ❌ Excepción: {str(e)[:80]}")
        
        if module not in self.results:
            self.results[module] = []
        
        self.results[module].append({
            'test': test_name,
            'result': result
        })
        
        print(f"  {result:20} {test_name:40}")
        time.sleep(0.3)
    
    def print_summary(self):
        """Imprimir resumen"""
        print(f"\n{'='*70}")
        print(f"RESUMEN DE PRUEBAS EXHAUSTIVAS")
        print(f"{'='*70}\n")
        
        for module in sorted(self.results.keys()):
            tests = self.results[module]
            total_m = len(tests)
            passed_m = sum(1 for t in tests if "✅" in t['result'])
            
            status = "✅" if passed_m == total_m else "⚠️"
            print(f"{status} {module:12} → {passed_m}/{total_m} tests pasaron")
        
        print(f"\n{'─'*70}")
        print(f"Total: {self.passed}/{self.total} tests pasaron")
        
        if self.passed == self.total:
            print(f"\n🎉 ¡ÉXITO! Todos los tests pasaron")
        else:
            print(f"\n⚠️  {self.total - self.passed} tests fallaron")
        
        print(f"{'='*70}\n")


def main():
    runner = ComprehensiveTestRunner()
    
    print("\n" + "="*70)
    print("🧪 TEST SUITE EXHAUSTIVO - FASES 1-3 REFACTORIZACIÓN")
    print("="*70)
    
    # =====================================================================
    # WAN TESTS
    # =====================================================================
    print("\n📦 MÓDULO: WAN")
    print("─"*70)
    
    # Happy path
    print("\n✅ Happy Path (funcionalidad normal):")
    runner.test("wan", "status (default)", "status", {}, expect_success=True)
    
    # Validación de parámetros
    print("\n❌ Validación de parámetros:")
    runner.test("wan", "config sin params", "config", {}, expect_success=False)
    runner.test("wan", "config interfaz inválida", "config", 
                {"action": "set_interface", "interface": "invalid0"}, expect_success=False)
    runner.test("wan", "config mode inválido", "config",
                {"action": "set_mode", "interface": "eno1", "mode": "invalid"}, expect_success=False)
    
    # =====================================================================
    # VLANS TESTS
    # =====================================================================
    print("\n📦 MÓDULO: VLANS")
    print("─"*70)
    
    # Happy path
    print("\n✅ Happy Path (funcionalidad normal):")
    runner.test("vlans", "status (inicial)", "status", {}, expect_success=True)
    runner.test("vlans", "start", "start", {}, expect_success=True)
    runner.test("vlans", "status (después start)", "status", {}, expect_success=True)
    runner.test("vlans", "config show", "config", {"action": "show"}, expect_success=True)
    runner.test("vlans", "stop", "stop", {}, expect_success=True)
    
    # Validación de parámetros
    print("\n❌ Validación de parámetros:")
    runner.test("vlans", "config sin action", "config", {}, expect_success=False)
    runner.test("vlans", "config action inválida", "config", 
                {"action": "invalid"}, expect_success=False)
    
    # Edge cases
    print("\n⚠️  Edge Cases (límites):")
    runner.test("vlans", "config add VLAN inválida", "config",
                {"action": "add", "id": "invalid", "name": "Test", "ip": "192.168.1.1/24"},
                expect_success=False)
    runner.test("vlans", "config add VLAN fuera de rango", "config",
                {"action": "add", "id": "5000", "name": "Test", "ip": "192.168.1.1/24"},
                expect_success=False)
    runner.test("vlans", "config add sin nombre", "config",
                {"action": "add", "id": "10"},
                expect_success=False)
    
    # =====================================================================
    # FIREWALL TESTS (FASE 3.1)
    # =====================================================================
    print("\n📦 MÓDULO: FIREWALL (Fase 3.1 - Refactorizado)")
    print("─"*70)
    
    # Happy path
    print("\n✅ Happy Path (funcionalidad normal):")
    runner.test("firewall", "status", "status", {}, expect_success=True)
    
    # Validación de parámetros - enable_whitelist
    print("\n❌ Validación de parámetros (enable_whitelist):")
    runner.test("firewall", "enable_whitelist sin VLAN", "enable_whitelist",
                {}, expect_success=False)
    runner.test("firewall", "enable_whitelist VLAN inválida", "enable_whitelist",
                {"vlan_id": "invalid"}, expect_success=False)
    runner.test("firewall", "enable_whitelist VLAN fuera rango", "enable_whitelist",
                {"vlan_id": "5000"}, expect_success=False)
    runner.test("firewall", "enable_whitelist sin whitelist", "enable_whitelist",
                {"vlan_id": "1"}, expect_success=False)
    runner.test("firewall", "enable_whitelist whitelist no es lista", "enable_whitelist",
                {"vlan_id": "1", "whitelist": "not_a_list"}, expect_success=False)
    
    # Validación de parámetros - disable_whitelist
    print("\n❌ Validación de parámetros (disable_whitelist):")
    runner.test("firewall", "disable_whitelist sin VLAN", "disable_whitelist",
                {}, expect_success=False)
    runner.test("firewall", "disable_whitelist VLAN inválida", "disable_whitelist",
                {"vlan_id": "invalid"}, expect_success=False)
    
    # Validación de parámetros - aislar
    print("\n❌ Validación de parámetros (aislar):")
    runner.test("firewall", "aislar sin VLAN", "aislar",
                {}, expect_success=False)
    runner.test("firewall", "aislar VLAN inválida", "aislar",
                {"vlan_id": "invalid"}, expect_success=False)
    runner.test("firewall", "aislar VLAN fuera rango", "aislar",
                {"vlan_id": "9999"}, expect_success=False)
    
    # Validación de parámetros - desaislar
    print("\n❌ Validación de parámetros (desaislar):")
    runner.test("firewall", "desaislar sin VLAN", "desaislar",
                {}, expect_success=False)
    runner.test("firewall", "desaislar VLAN inválida", "desaislar",
                {"vlan_id": "not_a_number"}, expect_success=False)
    
    # Validación de parámetros - restrict
    print("\n❌ Validación de parámetros (restrict):")
    runner.test("firewall", "restrict sin VLAN", "restrict",
                {}, expect_success=False)
    runner.test("firewall", "restrict VLAN inválida", "restrict",
                {"vlan_id": "abc"}, expect_success=False)
    runner.test("firewall", "restrict sin target_vlan", "restrict",
                {"vlan_id": "1"}, expect_success=False)
    runner.test("firewall", "restrict target_vlan inválido", "restrict",
                {"vlan_id": "1", "target_vlan": "xyz"}, expect_success=False)
    
    # Validación de parámetros - unrestrict
    print("\n❌ Validación de parámetros (unrestrict):")
    runner.test("firewall", "unrestrict sin VLAN", "unrestrict",
                {}, expect_success=False)
    runner.test("firewall", "unrestrict VLAN inválida", "unrestrict",
                {"vlan_id": "999999"}, expect_success=False)
    runner.test("firewall", "unrestrict sin target_vlan", "unrestrict",
                {"vlan_id": "1"}, expect_success=False)
    
    # =====================================================================
    # DMZ TESTS (FASE 3.2)
    # =====================================================================
    print("\n📦 MÓDULO: DMZ (Fase 3.2 - Refactorizado)")
    print("─"*70)
    
    # Happy path
    print("\n✅ Happy Path (funcionalidad normal):")
    runner.test("dmz", "status", "status", {}, expect_success=True)
    
    # Validación de parámetros - add_destination
    print("\n❌ Validación de parámetros (add_destination):")
    runner.test("dmz", "add_destination sin params", "add_destination",
                {}, expect_success=False)
    runner.test("dmz", "add_destination IP inválida", "add_destination",
                {"ip": "invalid_ip", "port": 80, "protocol": "tcp"}, expect_success=False)
    runner.test("dmz", "add_destination puerto inválido", "add_destination",
                {"ip": "192.168.1.100", "port": "invalid", "protocol": "tcp"}, expect_success=False)
    runner.test("dmz", "add_destination puerto fuera rango", "add_destination",
                {"ip": "192.168.1.100", "port": 70000, "protocol": "tcp"}, expect_success=False)
    runner.test("dmz", "add_destination protocolo inválido", "add_destination",
                {"ip": "192.168.1.100", "port": 80, "protocol": "invalid"}, expect_success=False)
    runner.test("dmz", "add_destination IP con máscara", "add_destination",
                {"ip": "192.168.1.0/24", "port": 80, "protocol": "tcp"}, expect_success=False)
    runner.test("dmz", "add_destination IP termina en 0", "add_destination",
                {"ip": "192.168.1.0", "port": 80, "protocol": "tcp"}, expect_success=False)
    runner.test("dmz", "add_destination IP termina en 255", "add_destination",
                {"ip": "192.168.1.255", "port": 80, "protocol": "tcp"}, expect_success=False)
    
    # Validación de parámetros - isolate_dmz_host (aislar)
    print("\n❌ Validación de parámetros (aislar):")
    runner.test("dmz", "aislar sin IP", "aislar",
                {}, expect_success=False)
    runner.test("dmz", "aislar IP inválida", "aislar",
                {"ip": "not_an_ip"}, expect_success=False)
    runner.test("dmz", "aislar IP pública", "aislar",
                {"ip": "8.8.8.8"}, expect_success=False)
    
    # Validación de parámetros - unisolate_dmz_host (desaislar)
    print("\n❌ Validación de parámetros (desaislar):")
    runner.test("dmz", "desaislar sin IP", "desaislar",
                {}, expect_success=False)
    runner.test("dmz", "desaislar IP inválida", "desaislar",
                {"ip": "300.400.500.600"}, expect_success=False)
    
    # =========================================================================
    # MÓDULO: EBTABLES (Fase 4 - Refactorizado)
    # =========================================================================
    print("\n" + "=" * 70)
    print("📦 MÓDULO: EBTABLES (Fase 4 - Refactorizado)")
    print("=" * 70)
    
    # Happy Path
    print("\n✅ Happy Path (funcionalidad normal):")
    runner.test("ebtables", "status", "status", {})
    
    # Happy Path - MAC whitelist (funcionalidad principal)
    print("\n✅ Happy Path - MAC Whitelist (funcionalidad principal):")
    runner.test("ebtables", "show_whitelist", "show_whitelist", {})
    runner.test("ebtables", "enable_whitelist", "enable_whitelist", {})
    # Limpieza: remover MAC si existe de tests anteriores (no cuenta como test)
    runner.test("ebtables", "remove_mac (limpieza)", "remove_mac",
                {"mac": "AA:BB:CC:DD:EE:FF"}, count_as_test=False)
    runner.test("ebtables", "add_mac válida", "add_mac",
                {"mac": "AA:BB:CC:DD:EE:FF"})
    runner.test("ebtables", "show_whitelist después de add", "show_whitelist", {})
    runner.test("ebtables", "remove_mac exitoso", "remove_mac",
                {"mac": "AA:BB:CC:DD:EE:FF"})
    runner.test("ebtables", "disable_whitelist", "disable_whitelist", {})
    
    # Validación de parámetros - aislar
    print("\n❌ Validación de parámetros (aislar):")
    runner.test("ebtables", "aislar sin vlan_id", "aislar",
                {}, expect_success=False)
    runner.test("ebtables", "aislar vlan_id inválido (string)", "aislar",
                {"vlan_id": "not_a_number"}, expect_success=False)
    runner.test("ebtables", "aislar vlan_id negativo", "aislar",
                {"vlan_id": -1}, expect_success=False)
    runner.test("ebtables", "aislar VLAN inexistente", "aislar",
                {"vlan_id": 9999}, expect_success=False)
    
    # Validación de parámetros - desaislar
    print("\n❌ Validación de parámetros (desaislar):")
    runner.test("ebtables", "desaislar sin vlan_id", "desaislar",
                {}, expect_success=False)
    runner.test("ebtables", "desaislar vlan_id inválido", "desaislar",
                {"vlan_id": "invalid"}, expect_success=False)
    runner.test("ebtables", "desaislar VLAN no configurada", "desaislar",
                {"vlan_id": 8888}, expect_success=False)
    
    # Validación de parámetros - config (MAC whitelist)
    print("\n❌ Validación de parámetros (MAC whitelist):")
    runner.test("ebtables", "add_mac sin MAC", "add_mac",
                {}, expect_success=False)
    runner.test("ebtables", "add_mac formato inválido", "add_mac",
                {"mac": "invalid_mac"}, expect_success=False)
    runner.test("ebtables", "add_mac formato parcial", "add_mac",
                {"mac": "AA:BB:CC"}, expect_success=False)
    runner.test("ebtables", "remove_mac sin MAC", "remove_mac",
                {}, expect_success=False)
    runner.test("ebtables", "remove_mac no existente", "remove_mac",
                {"mac": "FF:FF:FF:FF:FF:FF"}, expect_success=False)
    
    # Validación de dependencias
    print("\n❌ Validación de dependencias:")
    # Nota: Estos tests fallarán si WAN/VLANs/Tagging no están activos, lo cual es esperado
    runner.test("ebtables", "aislar sin dependencias", "aislar",
                {"vlan_id": 1}, expect_success=False)
    
    # =========================================================================
    # MÓDULO: EXPECT (Fase 5 - Automatización)
    # =========================================================================
    print("\n" + "=" * 70)
    print("📦 MÓDULO: EXPECT (Fase 5 - Automatización)")
    print("=" * 70)

    # Happy Path
    print("\n✅ Happy Path (funcionalidad normal):")
    runner.test("expect", "status", "status", {}, expect_success=True)
    
    # Auth config (necesario para tests posteriores)
    runner.test("expect", "auth configuration", "auth", 
                {"ip": "192.168.1.1", "user": "test", "password": "password"}, expect_success=True)
    
    # Soft Reset (dry-run)
    runner.test("expect", "reset (dry-run)", "reset", 
                {"ip": "192.168.1.1", "profile": "tp_link", "dry_run": True}, expect_success=True)

    # Port Security (dry-run)
    runner.test("expect", "port-security single (dry-run)", "port-security", 
                {"ip": "192.168.1.1", "ports": "1", "macs": "AA:BB:CC:DD:EE:FF", "dry_run": True}, 
                expect_success=True)
                
    runner.test("expect", "port-security range (dry-run)", "port-security", 
                {"ip": "192.168.1.1", "ports": "1,3-5", "macs": "AA:BB:CC:DD:EE:FF 11:22:33:44:55:66", "dry_run": True}, 
                expect_success=True)

    # Validación de parámetros - Config
    print("\n❌ Validación de parámetros (General/Config):")
    runner.test("expect", "config sin IP", "config", 
                {"actions": "hostname:Switch1"}, expect_success=False)
    runner.test("expect", "config sin actions", "config", 
                {"ip": "192.168.1.1"}, expect_success=False)

    # Validación de parámetros - Port Security (Strict)
    print("\n❌ Validación de parámetros (Port Security):")
    runner.test("expect", "port-security ports con espacios", "port-security", 
                {"ip": "1.1.1.1", "ports": "1, 2", "macs": "AA:BB:CC:DD:EE:FF", "dry_run": True}, 
                expect_success=False)
                
    runner.test("expect", "port-security MAC inválida", "port-security", 
                {"ip": "1.1.1.1", "ports": "1", "macs": "ZZ:ZZ:ZZ:ZZ:ZZ:ZZ", "dry_run": True}, 
                expect_success=False)
                
    runner.test("expect", "port-security sin MACs", "port-security", 
                {"ip": "1.1.1.1", "ports": "1", "dry_run": True}, 
                expect_success=False)
    
    # Imprimir resumen
    runner.print_summary()
    
    return 0 if runner.passed == runner.total else 1


if __name__ == "__main__":
    sys.exit(main())
