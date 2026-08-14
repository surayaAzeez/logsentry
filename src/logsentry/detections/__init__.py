"""Detection rules.

Importing this package registers every built-in rule in :data:`RULES`.
"""

from .base import RULES, Rule, register_rule, sliding_window
from .brute_force import BruteForceRule, PasswordSprayRule
from .impossible_travel import ImpossibleTravelRule
from .off_hours import OffHoursAccessRule, SuspiciousSudoRule
from .web_recon import SensitivePathProbeRule, WebScannerRule

__all__ = [
    "RULES",
    "Rule",
    "register_rule",
    "sliding_window",
    "BruteForceRule",
    "PasswordSprayRule",
    "ImpossibleTravelRule",
    "OffHoursAccessRule",
    "SuspiciousSudoRule",
    "WebScannerRule",
    "SensitivePathProbeRule",
]
