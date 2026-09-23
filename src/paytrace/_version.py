"""Single source for the version, importable without the package body.

Submodules read it from here rather than from the package, which would be a
circular import: the package __init__ imports those submodules before it has
finished defining __version__.
"""

__version__ = "2.0.5"
