# app/core/helpers/__init__.py
"""Helper modules para funcionalidades específicas de cada módulo core."""

from .helper_wan import verify_wan_status, verify_dhcp_assignment
from .helper_vlans import initialize_default_vlans, bridge_exists
from .helper_tagging import run_cmd, bridge_exists as tagging_bridge_exists, parse_vlan_range, format_vlan_list
from .helper_firewall import (
    ensure_dirs as firewall_ensure_dirs, load_firewall_config, load_vlans_config, load_wan_config, save_firewall_config,
    check_wan_configured as firewall_check_wan_configured, ensure_input_protection_chain, ensure_forward_protection_chain,
    setup_wan_protection, create_input_vlan_chain, create_forward_vlan_chain,
    remove_input_vlan_chain, remove_forward_vlan_chain, apply_whitelist, apply_single_whitelist_rule
)
from .helper_dmz import (
    ensure_dirs as dmz_ensure_dirs, write_log, load_config as dmz_load_config, save_config as dmz_save_config,
    load_wan_config as dmz_load_wan_config, load_firewall_config as dmz_load_firewall_config,
    load_vlans_config as dmz_load_vlans_config, get_vlan_from_ip,
    ensure_prerouting_protection_chain, ensure_prerouting_vlan_chain, remove_prerouting_vlan_chain,
    add_forward_accept_rule, remove_forward_accept_rule,
    check_wan_configured as dmz_check_wan_configured, check_firewall_active, check_vlans_active, validate_destination
)
from .helper_ebtables import (
    ensure_dirs as ebtables_ensure_dirs, load_ebtables_config, save_ebtables_config,
    load_vlans_config as ebtables_load_vlans_config, load_wan_config as ebtables_load_wan_config, load_tagging_config,
    build_vlan_interface_map, check_wan_active, check_vlans_active as ebtables_check_vlans_active,
    check_tagging_active, check_interface_vlan_conflict, check_vlan_already_isolated, check_dependencies,
    update_status as ebtables_update_status, run_ebtables,
    create_vlan_chain, delete_vlan_chain, add_vlan_interface_to_forward, remove_vlan_interface_from_forward,
    apply_isolation, remove_isolation,
    validate_mac_address, normalize_mac_address, apply_mac_whitelist_rules, remove_mac_whitelist_rules
)

__all__ = [
    # helper_wan
    'verify_wan_status',
    'verify_dhcp_assignment',
    # helper_vlans
    'initialize_default_vlans',
    'bridge_exists',
    # helper_tagging
    'run_cmd',
    'tagging_bridge_exists',
    'parse_vlan_range',
    'format_vlan_list',
    # helper_firewall
    'firewall_ensure_dirs',
    'load_firewall_config',
    'load_vlans_config',
    'load_wan_config',
    'save_firewall_config',
    'firewall_check_wan_configured',
    'ensure_input_protection_chain',
    'ensure_forward_protection_chain',
    'setup_wan_protection',
    'create_input_vlan_chain',
    'create_forward_vlan_chain',
    'remove_input_vlan_chain',
    'remove_forward_vlan_chain',
    'apply_whitelist',
    'apply_single_whitelist_rule',
    # helper_dmz
    'dmz_ensure_dirs',
    'write_log',
    'dmz_load_config',
    'dmz_save_config',
    'dmz_load_wan_config',
    'dmz_load_firewall_config',
    'dmz_load_vlans_config',
    'get_vlan_from_ip',
    'ensure_prerouting_protection_chain',
    'ensure_prerouting_vlan_chain',
    'remove_prerouting_vlan_chain',
    'add_forward_accept_rule',
    'remove_forward_accept_rule',
    'dmz_check_wan_configured',
    'check_firewall_active',
    'check_vlans_active',
    'validate_destination',
    # helper_ebtables
    'ebtables_ensure_dirs',
    'load_ebtables_config',
    'save_ebtables_config',
    'ebtables_load_vlans_config',
    'ebtables_load_wan_config',
    'load_tagging_config',
    'build_vlan_interface_map',
    'check_wan_active',
    'ebtables_check_vlans_active',
    'check_tagging_active',
    'check_interface_vlan_conflict',
    'check_vlan_already_isolated',
    'check_dependencies',
    'ebtables_update_status',
    'run_ebtables',
    'create_vlan_chain',
    'delete_vlan_chain',
    'add_vlan_interface_to_forward',
    'remove_vlan_interface_from_forward',
    'apply_isolation',
    'remove_isolation',
    'validate_mac_address',
    'normalize_mac_address',
    'apply_mac_whitelist_rules',
    'remove_mac_whitelist_rules',
]
