#!/usr/bin/env python3
"""Validate import boundaries defined in ARCHITECTURE.md.

This script checks that modules do not import from forbidden sources.
Run via: make check-architecture
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

# ── Import Rules ─────────────────────────────────────────────────
# Each key is a source module pattern. The value is a set of forbidden
# import prefixes. If a module under the source pattern imports from
# any of the forbidden prefixes, the check fails.

RULES: dict[str, set[str]] = {
    "mantle/interfaces/": {"mantle.capture", "mantle.ingest", "mantle.analysis", "mantle.server", "mantle_agent"},
    "mantle/errors.py": {"mantle.capture", "mantle.ingest", "mantle.analysis", "mantle.server", "mantle.interfaces", "mantle_agent"},
    "mantle/capture/": {"mantle.ingest", "mantle.analysis", "mantle.server", "mantle_agent"},
    "mantle/ingest/": {"mantle.capture", "mantle.server", "mantle_agent"},
    "mantle/analysis/": {"mantle.capture", "mantle.ingest", "mantle.server", "mantle_agent"},
    "mantle/server/": {"mantle.capture", "mantle_agent"},
    "mantle_agent/": {"mantle."},
}


def _extract_imports(filepath: Path) -> list[str]:
    """Extract all import module names from a Python file."""
    try:
        tree = ast.parse(filepath.read_text(), filename=str(filepath))
    except SyntaxError:
        return []

    modules: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                modules.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                modules.append(node.module)
    return modules


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    violations: list[str] = []

    for source_pattern, forbidden_prefixes in RULES.items():
        source_path = repo_root / source_pattern

        if source_path.is_file():
            files = [source_path]
        elif source_path.is_dir():
            files = list(source_path.rglob("*.py"))
        else:
            continue

        for filepath in files:
            rel = filepath.relative_to(repo_root)
            imports = _extract_imports(filepath)
            for imp in imports:
                for forbidden in forbidden_prefixes:
                    if imp == forbidden or imp.startswith(forbidden + ".") or (forbidden.endswith(".") and imp.startswith(forbidden)):
                        violations.append(
                            f"  {rel}: imports '{imp}' (forbidden by rule for {source_pattern})"
                        )

    if violations:
        print("❌ Architecture boundary violations found:\n")
        for v in violations:
            print(v)
        print(f"\n{len(violations)} violation(s). See ARCHITECTURE.md for import rules.")
        return 1

    print("✅ All import boundaries respected.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
