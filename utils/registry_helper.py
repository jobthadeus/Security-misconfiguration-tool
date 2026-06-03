"""
Safe Windows registry access helpers.

Many security settings on Windows are stored in the registry. These helpers
wrap winreg with consistent error handling so scanners fail gracefully when
keys are missing or access is denied (common without admin privileges).
"""

from __future__ import annotations

import winreg
from typing import Any


# Map friendly hive names to winreg constants
HIVES = {
    "HKLM": winreg.HKEY_LOCAL_MACHINE,
    "HKCU": winreg.HKEY_CURRENT_USER,
    "HKU": winreg.HKEY_USERS,
}


def read_registry_value(
    hive: str,
    path: str,
    name: str,
    default: Any = None,
) -> Any:
    """
    Read a single registry value.

    Returns `default` if the key/value does not exist or cannot be opened.
    """
    hive_key = HIVES.get(hive.upper())
    if hive_key is None:
        return default

    try:
        with winreg.OpenKey(hive_key, path, 0, winreg.KEY_READ) as key:
            value, _reg_type = winreg.QueryValueEx(key, name)
            return value
    except OSError:
        return default


def registry_key_exists(hive: str, path: str) -> bool:
    """Return True if the registry path exists and is readable."""
    hive_key = HIVES.get(hive.upper())
    if hive_key is None:
        return False

    try:
        with winreg.OpenKey(hive_key, path, 0, winreg.KEY_READ):
            return True
    except OSError:
        return False


def enum_registry_values(hive: str, path: str) -> dict[str, Any]:
    """
    Enumerate all values under a registry key.

    Useful for autorun locations (Run/RunOnce keys) where each value is a
    startup entry.
    """
    hive_key = HIVES.get(hive.upper())
    if hive_key is None:
        return {}

    results: dict[str, Any] = {}
    try:
        with winreg.OpenKey(hive_key, path, 0, winreg.KEY_READ) as key:
            index = 0
            while True:
                try:
                    name, value, _reg_type = winreg.EnumValue(key, index)
                    results[name] = value
                    index += 1
                except OSError:
                    break
    except OSError:
        pass

    return results
