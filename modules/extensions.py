"""
Extension loader.

An extension is a Python module placed in the extensions directory that exposes a
`register(api)` function. It receives an ExtensionAPI it can use to add passive
checks, addons, Repeater actions, or (if the operator supplies them) active-scan
checks. This is the plugin seam that makes the tool extensible like Burp's BApp
store or ZAP add-ons.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

from core.interceptor import Interceptor, BaseAddon
from modules.passive_scanner import PassiveScanner, PassiveCheck
from modules.active_scan import ActiveScanEngine, ActiveCheck


class ExtensionAPI:
    """Handed to each extension's register() function."""

    def __init__(self, interceptor: Interceptor,
                 passive: PassiveScanner, active: ActiveScanEngine) -> None:
        self._interceptor = interceptor
        self._passive = passive
        self._active = active
        self.loaded: list[str] = []

    def add_addon(self, addon: BaseAddon) -> None:
        self._interceptor.add(addon)

    def add_passive_check(self, check: PassiveCheck) -> None:
        self._passive.checks.append(check)

    def add_active_check(self, check: ActiveCheck) -> None:
        """Register an active check. The operator is responsible for only using
        active checks against targets they are authorized to test."""
        self._active.register(check)


class ExtensionManager:
    def __init__(self, api: ExtensionAPI, ext_dir: str | Path = "extensions") -> None:
        self.api = api
        self.ext_dir = Path(ext_dir)

    def load_all(self) -> list[str]:
        if not self.ext_dir.exists():
            return []
        for path in sorted(self.ext_dir.glob("*.py")):
            if path.name.startswith("_"):
                continue
            self._load_one(path)
        return self.api.loaded

    def _load_one(self, path: Path) -> None:
        spec = importlib.util.spec_from_file_location(f"ext_{path.stem}", path)
        if not spec or not spec.loader:
            return
        mod = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = mod
        try:
            spec.loader.exec_module(mod)
            if hasattr(mod, "register"):
                mod.register(self.api)
                self.api.loaded.append(path.stem)
                print(f"[ext] loaded {path.stem}")
            else:
                print(f"[ext] {path.stem} has no register(api); skipped")
        except Exception as exc:
            print(f"[ext] failed to load {path.stem}: {exc!r}")
