"""Parser plumbing.

A parser turns raw text lines into :class:`~logsentry.models.LogEvent` objects.
Subclasses implement :meth:`Parser.parse_line` and set ``name``; everything
else (file handling, encoding fallbacks, skip counting) is handled here.
"""

from __future__ import annotations

import gzip
from abc import ABC, abstractmethod
from collections.abc import Iterable, Iterator
from datetime import datetime
from pathlib import Path

from ..models import LogEvent


class Parser(ABC):
    """Base class for all log parsers."""

    name: str = "base"

    def __init__(self, default_year: int | None = None) -> None:
        # Syslog-style timestamps famously omit the year, so callers can pin it.
        self.default_year = default_year or datetime.now().year
        self.skipped = 0

    @abstractmethod
    def parse_line(self, line: str) -> LogEvent | None:
        """Return a LogEvent, or ``None`` if the line is not of interest."""

    def sniff(self, sample: Iterable[str]) -> bool:
        """Return True when this parser recognises the given sample lines.

        Used by :func:`detect_parser` for format auto-detection.
        """
        hits = 0
        for line in sample:
            if self.parse_line(line) is not None:
                hits += 1
        return hits > 0

    def parse_lines(self, lines: Iterable[str]) -> Iterator[LogEvent]:
        for line in lines:
            line = line.rstrip("\n")
            if not line.strip():
                continue
            event = self.parse_line(line)
            if event is None:
                self.skipped += 1
                continue
            yield event

    def parse_file(self, path: str | Path) -> Iterator[LogEvent]:
        """Parse a file, transparently handling ``.gz`` and bad bytes."""
        path = Path(path)
        if path.suffix == ".gz":
            with gzip.open(path, "rt", encoding="utf-8", errors="replace") as fh:
                yield from self.parse_lines(fh)
        else:
            with path.open("r", encoding="utf-8", errors="replace") as fh:
                yield from self.parse_lines(fh)


def _head(lines: Iterable[str], limit: int = 25) -> list[str]:
    """First ``limit`` non-empty lines, used for format sniffing."""
    sample: list[str] = []
    for line in lines:
        if line.strip():
            sample.append(line)
        if len(sample) >= limit:
            break
    return sample


def detect_parser(path: str | Path, year: int | None = None) -> Parser:
    """Pick a parser by peeking at the first non-empty lines of a file.

    Falling back to the sshd parser keeps the CLI usable on odd files rather
    than hard-failing; the caller sees a zero-event run and can pass
    ``--format`` explicitly.
    """
    from .nginx import NginxAccessParser
    from .sshd import SSHDParser
    from .windows import WindowsSecurityCSVParser

    path = Path(path)
    if path.suffix == ".gz":
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as fh:
            sample = _head(fh)
    else:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            sample = _head(fh)

    candidates: list[Parser] = [
        SSHDParser(default_year=year),
        NginxAccessParser(default_year=year),
        WindowsSecurityCSVParser(default_year=year),
    ]
    for parser in candidates:
        if parser.sniff(sample):
            return parser
    return SSHDParser(default_year=year)


PARSERS: dict[str, type[Parser]] = {}


def register(cls: type[Parser]) -> type[Parser]:
    """Class decorator so ``--format <name>`` resolves without a manual table."""
    PARSERS[cls.name] = cls
    return cls
