"""
my/modules/__init__.py

Auto-discovers and exports all attack modules in this package.
Each module file must be named mod_*.py and contain a class
that inherits from BaseModule.
"""

import importlib
import pkgutil
import inspect
import logging
from pathlib import Path
from typing import List, Type

from my_scan.modules.base import BaseModule

logger = logging.getLogger("ModuleLoader")


def load_all_modules() -> List[Type[BaseModule]]:
    """
    Dynamically imports every mod_*.py in this package and
    returns a list of all BaseModule subclasses found.
    """
    modules: List[Type[BaseModule]] = []
    package_dir = Path(__file__).parent

    for finder, module_name, is_pkg in pkgutil.iter_modules([str(package_dir)]):
        if not module_name.startswith("mod_"):
            continue
        full_name = f"my_scan.modules.{module_name}"
        try:
            mod = importlib.import_module(full_name)
            for name, obj in inspect.getmembers(mod, inspect.isclass):
                if issubclass(obj, BaseModule) and obj is not BaseModule:
                    modules.append(obj)
                    logger.debug(f"Loaded module: {obj.name} ({full_name}.{name})")
        except Exception as exc:
            logger.warning(f"Failed to load module '{full_name}': {exc}")

    logger.info(f"[ModuleLoader] Loaded {len(modules)} attack module(s): "
                f"{[m.name for m in modules]}")
    return modules


# Pre-load at import time so callers can use:
#   from my_scan.modules import ALL_MODULES
ALL_MODULES = load_all_modules()
