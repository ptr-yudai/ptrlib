"""Sphinx configuration for ptrlib.

This project intentionally prefers source-based API generation (AutoAPI)
so that docs build does not require importing ptrlib (which may depend on
external tools such as assemblers/disassemblers).
"""

from __future__ import annotations

from datetime import datetime


project = "ptrlib"
author = "ptr-yudai"
copyright = f"{datetime.now().year}, {author}"


extensions = [
    "sphinx.ext.autosectionlabel",
    "sphinx.ext.intersphinx",
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
    "autoapi.extension",
]


templates_path = ["_templates"]
exclude_patterns: list[str] = []


html_theme = "furo"
html_static_path = ["_static"]


autosectionlabel_prefix_document = True


intersphinx_mapping = {
    # Sphinx>=8 requires explicit inventory location (non-empty string) or None.
    "python": ("https://docs.python.org/3", "https://docs.python.org/3/objects.inv"),
}


# --- AutoAPI (API reference from docstrings, without importing ptrlib) ---
autoapi_type = "python"
autoapi_dirs = ["../../ptrlib"]
autoapi_root = "autoapi"
autoapi_add_toctree_entry = False
autoapi_keep_files = True

# Keep the output relatively small (the project is large)
autoapi_options = [
    "members",
    "undoc-members",
    "show-inheritance",
    "show-module-summary",
]

# Keep builds clean: AutoAPI's import-resolution warnings are not docstring issues.
suppress_warnings = [
    "autoapi.python_import_resolution",
]
