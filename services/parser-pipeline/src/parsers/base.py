"""Abstract base classes for log parsers."""
from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
import uuid

# ---------------------------------------------------------------------------
# Syslog timestamp patterns
# ---------------------------------------------------------------------------

# RFC 3164: "Jan  1 00:00:00" or "Jan 01 00:00:00"
_RFC3164_TS = re.compile(
    r"^(?P<mon>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+"
    r"(?P<day>\d{1,2})\s+(?P<hh>\d{2}):(?P<mm>\d{2}):(?P<ss>\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<prog>\S+?)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.+)"
)

# RFC 5424: "2024-01-01T00:00:00.000Z"
_RFC5424_TS = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))\s+"
    r"(?P<host>\S+)\s+(?P<prog>\S+)\s+\S+\s+\S+\s+\S+\s+(?P<msg>.+)"
)

# Kernel messages: "<N>timestamp host kernel: msg"
_KERNEL_TS = re.compile(
    r"^(?:<\d+>)?\s*(?P<ts>\S+\s+\S+\s+\S+)\s+(?P<host>\S+)\s+kernel:\s*(?P<msg>.+)"
)

_MONTH_MAP = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


@dataclass
class ParsedEvent:
    timestamp: datetime
    dataset: str
    event_kind: str = "event"
    event_category: list[str] = field(default_factory=list)
    event_type: list[str] = field(default_factory=list)
    event_severity: int = 5
    event_outcome: str = "unknown"
    source_ip: Optional[str] = None
    source_port: Optional[int] = None
    source_mac: Optional[str] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None
    network_protocol: Optional[str] = None
    network_direction: str = "unknown"
    network_bytes: int = 0
    network_packets: int = 0
    hostname: Optional[str] = None
    username: Optional[str] = None
    observer_type: str = "firewall"
    tags: list[str] = field(default_factory=list)
    labels: dict = field(default_factory=dict)
    message: str = ""
    raw_message: str = ""


class BaseParser(ABC):
    """Abstract base class for all log parsers."""

    @abstractmethod
    def can_parse(self, raw: str, program: Optional[str], hostname: Optional[str]) -> bool:
        """Return True if this parser can handle the given log line."""
        ...

    @abstractmethod
    def parse(self, raw: str, source_ip: str, received_at: datetime) -> Optional[ParsedEvent]:
        """
        Parse the raw log line and return a ParsedEvent, or None on failure.
        Never raises — return None instead.
        """
        ...

    def _extract_syslog_header(
        self, raw: str
    ) -> tuple[Optional[datetime], Optional[str], Optional[str], str]:
        """
        Extract (timestamp, hostname, program, message) from a syslog line.

        Supports:
        - RFC 5424: 2024-01-01T00:00:00Z host prog msgid structured msg
        - RFC 3164: Jan  1 00:00:00 host prog[pid]: msg
        - PRI-prefixed: <N>Jan  1 00:00:00 ...
        - Bare kernel messages

        Returns (ts, hostname, program, message). Any field may be None/empty.
        """
        # Strip optional PRI prefix "<N>"
        stripped = re.sub(r"^<\d+>", "", raw).strip()

        # Try RFC 5424
        m = _RFC5424_TS.match(stripped)
        if m:
            try:
                ts_str = m.group("ts")
                ts_str = ts_str.replace("Z", "+00:00")
                ts = datetime.fromisoformat(ts_str).astimezone(timezone.utc).replace(tzinfo=timezone.utc)
            except ValueError:
                ts = None
            return ts, m.group("host"), m.group("prog"), m.group("msg")

        # Try RFC 3164
        m = _RFC3164_TS.match(stripped)
        if m:
            now = datetime.now(timezone.utc)
            try:
                ts = datetime(
                    year=now.year,
                    month=_MONTH_MAP[m.group("mon")],
                    day=int(m.group("day")),
                    hour=int(m.group("hh")),
                    minute=int(m.group("mm")),
                    second=int(m.group("ss")),
                    tzinfo=timezone.utc,
                )
                # Handle year rollover (Dec -> Jan)
                if ts > now and ts.month > now.month:
                    ts = ts.replace(year=now.year - 1)
            except (ValueError, KeyError):
                ts = None
            prog = m.group("prog")
            return ts, m.group("host"), prog, m.group("msg")

        # Fallback: return the whole line as message
        return None, None, None, stripped

    @staticmethod
    def _safe_int(value: Optional[str], default: int = 0) -> int:
        """Safely convert a string to int."""
        if value is None:
            return default
        try:
            return int(value)
        except (ValueError, TypeError):
            return default
