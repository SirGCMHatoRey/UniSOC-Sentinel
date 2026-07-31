"""Parser for UniFi threat management / IPS block log entries."""
from __future__ import annotations

import re
from datetime import datetime
from typing import Optional

from .base import BaseParser, ParsedEvent

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------
# ubnt-threat-management: BLOCK src=1.2.3.4 dst=5.6.7.8 threat=Mirai.Botnet
_THREAT_MGMT_BLOCK = re.compile(
    r"(?:ubnt-threat-management|threat-management).*?"
    r"(?P<action>BLOCK|ALLOW|DROP|ALERT)\s+"
    r"(?:.*?src=(?P<src>[\d.]+))?(?:.*?dst=(?P<dst>[\d.]+))?"
    r"(?:.*?threat=(?P<threat>\S+))?(?:.*?url=(?P<url>\S+))?",
    re.IGNORECASE,
)

# IPS block: [IPS] Blocked <ip> - <threat_name>
_IPS_BLOCK_SIMPLE = re.compile(
    r"\[IPS\]\s+(?P<action>Blocked|Detected|Allowed)\s+(?P<ip>[\d.]+)\s+-\s+(?P<threat>.+?)(?:\s*$)",
    re.IGNORECASE,
)

# Malware detected: malware detected <name> from <ip>
_MALWARE_DETECTED = re.compile(
    r"malware\s+detected[:\s]+(?P<threat>\S+).*?from\s+(?P<ip>[\d.]+)",
    re.IGNORECASE,
)

# Generic threat blocked: Blocked <threat> from/at <ip>
_GENERIC_THREAT_BLOCK = re.compile(
    r"(?:Blocked|Dropped)\s+(?P<threat>\S+).*?(?:from|at)\s+(?P<ip>[\d.]+)",
    re.IGNORECASE,
)

# honeypot / canary trigger
_HONEYPOT = re.compile(
    r"(?:honeypot|canary).*?(?:triggered|hit).*?(?:from\s+(?P<ip>[\d.]+))?",
    re.IGNORECASE,
)

# DPI: deep packet inspection block
_DPI_BLOCK = re.compile(
    r"DPI:\s*(?P<action>BLOCKED|ALLOWED)\s+(?P<cat>\S+).*?src=(?P<src>[\d.]+).*?dst=(?P<dst>[\d.]+)",
    re.IGNORECASE,
)

_THREAT_PROGRAMS = frozenset({
    "ubnt-threat-management", "threat-management", "ubnt-ips", "suricata",
    "snort", "honeypot", "malware-detect",
})
_THREAT_KEYWORDS = re.compile(
    r"ubnt-threat-management|threat=|malware detected|\[IPS\]"
    r"|DPI:.*BLOCK|honeypot.*triggered|Blocked.*threat",
    re.IGNORECASE,
)


class ThreatParser(BaseParser):
    """Parse UniFi threat management and IPS block log events."""

    def can_parse(self, raw: str, program: Optional[str], hostname: Optional[str]) -> bool:
        prog_match = program and program.lower().split("[")[0] in _THREAT_PROGRAMS
        kw_match = bool(_THREAT_KEYWORDS.search(raw))
        return bool(prog_match or kw_match)

    def parse(self, raw: str, source_ip: str, received_at: datetime) -> Optional[ParsedEvent]:
        try:
            return self._parse(raw, source_ip, received_at)
        except Exception:
            return None

    def _parse(self, raw: str, source_ip: str, received_at: datetime) -> Optional[ParsedEvent]:
        ts, hostname, program, msg = self._extract_syslog_header(raw)
        ts = ts or received_at

        # ubnt-threat-management block
        m = _THREAT_MGMT_BLOCK.search(raw)
        if m:
            action = m.group("action").upper()
            threat_name = m.group("threat") or "unknown"
            src = m.group("src")
            dst = m.group("dst")
            blocked = action in ("BLOCK", "DROP")
            return _threat_event(
                ts=ts, hostname=hostname, raw=raw,
                threat_name=threat_name,
                src_ip=src, dst_ip=dst,
                blocked=blocked,
                msg=f"Threat {'blocked' if blocked else 'detected'}: {threat_name} from {src or '?'} to {dst or '?'}",
                labels={"url": m.group("url") or ""},
            )

        # IPS block simple
        m = _IPS_BLOCK_SIMPLE.search(raw)
        if m:
            blocked = m.group("action").lower() == "blocked"
            return _threat_event(
                ts=ts, hostname=hostname, raw=raw,
                threat_name=m.group("threat"),
                src_ip=m.group("ip"),
                blocked=blocked,
                msg=f"IPS {m.group('action').lower()}: {m.group('threat')} from {m.group('ip')}",
            )

        # Malware detected
        m = _MALWARE_DETECTED.search(raw)
        if m:
            return _threat_event(
                ts=ts, hostname=hostname, raw=raw,
                threat_name=m.group("threat"),
                src_ip=m.group("ip"),
                blocked=True,
                msg=f"Malware detected: {m.group('threat')} from {m.group('ip')}",
                severity=9,
            )

        # DPI block
        m = _DPI_BLOCK.search(raw)
        if m:
            blocked = m.group("action").upper() == "BLOCKED"
            return _threat_event(
                ts=ts, hostname=hostname, raw=raw,
                threat_name=m.group("cat"),
                src_ip=m.group("src"), dst_ip=m.group("dst"),
                blocked=blocked,
                msg=f"DPI {m.group('action').lower()}: {m.group('cat')} from {m.group('src')}",
                labels={"dpi_category": m.group("cat")},
            )

        # Honeypot trigger
        m = _HONEYPOT.search(raw)
        if m:
            ip = m.group("ip") if m.lastindex and m.lastindex >= 1 else None
            return _threat_event(
                ts=ts, hostname=hostname, raw=raw,
                threat_name="honeypot_trigger",
                src_ip=ip, blocked=False,
                msg=f"Honeypot triggered from {ip or 'unknown'}",
                severity=9,
            )

        # Generic threat block
        m = _GENERIC_THREAT_BLOCK.search(raw)
        if m:
            return _threat_event(
                ts=ts, hostname=hostname, raw=raw,
                threat_name=m.group("threat"),
                src_ip=m.group("ip"),
                blocked=True,
                msg=f"Threat blocked: {m.group('threat')} from {m.group('ip')}",
            )

        return None


def _threat_event(
    ts: datetime,
    hostname: Optional[str],
    raw: str,
    threat_name: str,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    blocked: bool = True,
    msg: str = "",
    severity: int = 8,
    labels: Optional[dict] = None,
) -> ParsedEvent:
    lbl = {"threat_name": threat_name}
    if labels:
        lbl.update(labels)
    outcome = "failure" if blocked else "unknown"
    ev_type = ["denied"] if blocked else ["info"]
    return ParsedEvent(
        timestamp=ts,
        dataset="unifi.threat",
        event_kind="alert",
        event_category=["intrusion_detection"],
        event_type=ev_type,
        event_severity=severity,
        event_outcome=outcome,
        source_ip=src_ip,
        dest_ip=dst_ip,
        hostname=hostname,
        observer_type="ids",
        tags=["threat", "ips"],
        labels=lbl,
        message=msg,
        raw_message=raw,
    )
