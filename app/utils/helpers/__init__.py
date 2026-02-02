# app/utils/helpers/__init__.py
"""
Helper modules para funcionalidades comunes en JSBach V4.0
"""

from .module_helpers import (
    load_json_config,
    save_json_config,
    update_module_status,
    get_module_status,
    run_command,
    validate_interface_name,
    interface_exists,
    load_module_config,
    get_wan_interface,
    ensure_module_dirs,
    get_config_file_path,
    get_log_file_path,
)

from .status_helpers import (
    format_status_header,
    format_status_section,
    format_active_status,
    format_configuration_list,
    build_status_response,
    validate_config_structure,
    validate_config_has_status,
    check_module_dependency,
    check_multiple_dependencies,
    find_new_items,
    find_removed_items,
)

from .network_helpers import (
    validate_vlan_range,
    validate_vlan_name,
    parse_cidr,
    get_network_address,
    get_broadcast_address,
    is_ip_in_subnet,
    validate_port_range,
    bridge_exists,
    get_bridge_members,
    vlan_interface_exists,
    get_interface_ip,
    is_interface_up,
)

from .io_helpers import (
    get_module_logger,
    write_log_file,
    clear_log_file,
    read_log_file,
    ensure_directory_exists,
    ensure_file_exists,
    list_directory_files,
    remove_file,
    write_json_file,
    read_json_file,
    backup_file,
    restore_from_backup,
    cleanup_old_logs,
)

__all__ = [
    # module_helpers
    'load_json_config',
    'save_json_config',
    'update_module_status',
    'get_module_status',
    'run_command',
    'validate_interface_name',
    'interface_exists',
    'load_module_config',
    'get_wan_interface',
    'ensure_module_dirs',
    'get_config_file_path',
    'get_log_file_path',
    # status_helpers
    'format_status_header',
    'format_status_section',
    'format_active_status',
    'format_configuration_list',
    'build_status_response',
    'validate_config_structure',
    'validate_config_has_status',
    'check_module_dependency',
    'check_multiple_dependencies',
    'find_new_items',
    'find_removed_items',
    # network_helpers
    'validate_vlan_range',
    'validate_vlan_name',
    'parse_cidr',
    'get_network_address',
    'get_broadcast_address',
    'is_ip_in_subnet',
    'validate_port_range',
    'bridge_exists',
    'get_bridge_members',
    'vlan_interface_exists',
    'get_interface_ip',
    'is_interface_up',
    # io_helpers
    'get_module_logger',
    'write_log_file',
    'clear_log_file',
    'read_log_file',
    'ensure_directory_exists',
    'ensure_file_exists',
    'list_directory_files',
    'remove_file',
    'write_json_file',
    'read_json_file',
    'backup_file',
    'restore_from_backup',
    'cleanup_old_logs',
]
