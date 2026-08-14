"""Log parsers. Import a concrete parser, or let ``detect_parser`` choose."""

from .base import PARSERS, Parser, detect_parser, register
from .nginx import NginxAccessParser
from .sshd import SSHDParser
from .windows import WindowsSecurityCSVParser

__all__ = [
    "PARSERS",
    "Parser",
    "detect_parser",
    "register",
    "SSHDParser",
    "NginxAccessParser",
    "WindowsSecurityCSVParser",
]
