"""Fixed read-only checks after a model-specific temporary root check."""

FRAMEWORK_FILES = {
    name: f"/usr/share/dotnet.tizen/framework/{name}"
    for name in ("Tizen.NUI.dll", "Tizen.Applications.Common.dll", "Tizen.System.dll", "Tizen.dll")
}

ROOT_INVENTORY_COMMANDS = (
    (
        "platform",
        "cat /etc/os-release; uname -srmo; getconf LONG_BIT; "
        "readlink -f /usr/share/dotnet.tizen/netcoreapp",
    ),
    (
        "framework_paths",
        "find /usr/share/dotnet.tizen -name Tizen.NUI.dll "
        "-o -name Tizen.Applications.Common.dll "
        "-o -name Tizen.System.dll -o -name Tizen.dll",
    ),
    (
        "framework_sizes",
        "stat -c '%n|%s' /usr/share/dotnet.tizen/framework/Tizen.NUI.dll "
        "/usr/share/dotnet.tizen/framework/Tizen.Applications.Common.dll "
        "/usr/share/dotnet.tizen/framework/Tizen.System.dll "
        "/usr/share/dotnet.tizen/framework/Tizen.dll",
    ),
    (
        "installed_app_registry",
        "sqlite3 -readonly -separator '|' /opt/dbspace/.pkgmgr_parser.db "
        "'SELECT app_id,app_disable,app_onboot,app_autorestart,app_preload,app_root_path "
        "FROM package_app_info ORDER BY app_id;'",
    ),
    (
        "settings_key_routes",
        "sqlite3 -readonly -separator '|' /opt/dbspace/.app-context.db "
        "\"SELECT appid,key,target_selector,args FROM key_filter "
        "WHERE key IN ('XF86More','XF86SysMenu') ORDER BY appid,key;\"",
    ),
    ("home_preference", "vconftool get db/appfw/home_appid"),
    ("startup_preference", "vconftool get db/appfw/startup_appid"),
    (
        "service_conditions",
        "systemctl cat pisa-service.service canalysis-service.service",
    ),
)
