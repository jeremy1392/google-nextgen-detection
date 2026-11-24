"""Baseline (normal) activity generators, one module per box of the architecture diagram."""
from __future__ import annotations

from . import admin, borg, corp, observability, runtime, storage

MODULES = (corp, admin, borg, storage, runtime, observability)


def install_all(sim, w) -> None:
    for module in MODULES:
        module.install(sim, w)
