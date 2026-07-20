"""Phase 2 isolated lab: scoped attacks against owned equipment only."""

from .scope import LabScope, ScopeError, load_lab_config

__all__ = ["LabScope", "ScopeError", "load_lab_config"]
