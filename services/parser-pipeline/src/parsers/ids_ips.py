"""Parser for Snort / Suricata IDS/IPS log entries."""
from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Optional

from .base import BaseParser, ParsedEvent

# ---------------------------------------------------------------------------
# Snort alert pattern
# [**] [1:2100498:7] GPL ATTACK_RESPONSE id check returned root [**]
# [Classification: Potentially Bad Traffic] [Priority: 2]
# 01/01-00:00:00.000000 1.2.3.4:54321 -> 5.6.7.8:80
# {TCP} 1.2.3.4:54321 -> 5.6.7.8:80
# ---------------------------------------------------------------------------
_SNORT_HEADER = re.compile(
    r"\[\*\*\]\s+\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+(?P<name>.+?)\s+\[\*\*\]",
)
_SNORT_CLASS = re.compile(
    r"\[Classification:\s+(?P<cls>[^\]]+)\]",
)
_SNORT_PRIORITY = re.compile(
    r"\[Priority:\s+(?P<pri>\d+)\]",
)
_SNORT_HOSTS = re.compile(
    r"\{(?P<proto>\w+)\}\s+(?P<src>[\d.]+)(?::(?P<spt>\d+))?\s+->\s+(?P<dst>[\d.]+)(?::(?P<dpt>\d+))?",
)

# ---------------------------------------------------------------------------
# Suricata alert (fast.log format)
# 01/01/2024-00:00:00.000000  [**] [1:2001219:20] ET SCAN Potential SSH Scan [**]
# [Classification: Attempted Information Leak] [Priority: 2] {TCP} 1.2.3.4:54321 -> 5.6.7.8:22
# ---------------------------------------------------------------------------
_SURICATA_FAST_TS = re.compile(
    r"^\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}\.\d+\s+",
)

# Suricata EVE JSON — detect if raw is JSON with event_type: alert
_SURICATA_JSON_HINT = re.compile(r'"event_type"\s*:\s*"alert"')

# Generic IDS single-line: IDS Alert: <sig> SRC:<ip> DST:<ip>
_IDS_GENERIC = re.compile(
    r"(?:IDS Alert|IPS Alert|ALERT)[:\s]+(?P<sig>[^;]+?);\s*SRC:(?P<src>[\d.]+).*?DST:(?P<dst>[\d.]+)",
    re.IGNORECASE,
)

_IDS_PROGRAMS = frozenset({"snort", "suricata", "barnyard2", "unified2", "alert_fast"})
_IDS_KEYWORDS = re.compile(
    r"\[\*\*\].*\[\*\*\]|\[Classification:|\[Priority:\s*\d\]"
    r"|\"event_type\":\s*\"alert\""
    r"|IDS Alert:|IPS Alert:",
    re.IGNORECASE,
)

# Map Snort priority to ECS severity (1=high, 4=low, inverse)
_PRIORITY_TO_SEVERITY = {1: 9, 2: 7, 3: 5, 4: 3}


class IDSIPSParser(BaseParser):
    """Parse Snort and Suricata IDS/IPS alert log entries."""

    def can_parse(self, raw: str, program: Optional[str], hostname: Optional[str]) -> bool:
        prog_match = program and program.lower().split("[")[0] in _IDS_PROGRAMS
        kw_match = bool(_IDS_KEYWORDS.search(raw))
        return bool(prog_match or kw_match)

    def parse(self, raw: str, source_ip: str, received_at: datetime) -> Optional[ParsedEvent]:
        try:
            return self._parse(raw, source_ip, received_at)
        except Exception:
            return None

    def _parse(self, raw: str, source_ip: str, received_at: datetime) -> Optional[ParsedEvent]:
        ts, hostname, program, msg = self._extract_syslog_header(raw)
        ts = ts or received_at

        # Suricata EVE JSON
        if _SURICATA_JSON_HINT.search(raw):
            return self._parse_suricata_json(raw, ts, hostname, received_at)

        # Snort / Suricata fast format
        m_hdr = _SNORT_HEADER.search(raw)
        if m_hdr:
            return self._parse_snort_alert(raw, m_hdr, ts, hostname)

        # Generic IDS
        m = _IDS_GENERIC.search(raw)
        if m:
            return _ids_event(
                ts=ts, hostname=hostname, raw=raw,
                sig_name=m.group("sig").strip(),
                src_ip=m.group("src"), dst_ip=m.group("dst"),
                msg=f"IDS alert: {m.group('sig').strip()}",
            )

        return None

    def _parse_snort_alert(
        self, raw: str, m_hdr: re.Match, ts: datetime, hostname: Optional[str]
    ) -> ParsedEvent:
        sig_id = f"{m_hdr.group('gid')}:{m_hdr.group('sid')}:{m_hdr.group('rev')}"
        sig_name = m_hdr.group("name").strip()

        m_cls = _SNORT_CLASS.search(raw)
        classification = m_cls.group("cls").strip() if m_cls else "unknown"

        m_pri = _SNORT_PRIORITY.search(raw)
        priority = int(m_pri.group("pri")) if m_pri else 3
        severity = _PRIORITY_TO_SEVERITY.get(priority, 5)

        m_hosts = _SNORT_HOSTS.search(raw)
        src_ip = m_hosts.group("src") if m_hosts else None
        spt = self._safe_int(m_hosts.group("spt")) if m_hosts and m_hosts.group("spt") else None
        dst_ip = m_hosts.group("dst") if m_hosts else None
        dpt = self._safe_int(m_hosts.group("dpt")) if m_hosts and m_hosts.group("dpt") else None
        proto = m_hosts.group("proto").lower() if m_hosts else None

        return _ids_event(
            ts=ts, hostname=hostname, raw=raw,
            sig_name=sig_name, sig_id=sig_id,
            classification=classification, priority=priority,
            src_ip=src_ip, src_port=spt, dst_ip=dst_ip, dst_port=dpt,
            protocol=proto, severity=severity,
            msg=f"IDS/IPS alert [{sig_id}]: {sig_name} (Priority {priority})",
        )

    def _parse_suricata_json(
        self, raw: str, ts: datetime, hostname: Optional[str], received_at: datetime
    ) -> Optional[ParsedEvent]:
        # Find JSON object in the raw string
        json_start = raw.find("{")
        if json_start == -1:
            return None
        try:
            data = json.loads(raw[json_start:])
        except json.JSONDecodeError:
            return None

        alert = data.get("alert", {})
        sig_name = alert.get("signature", "unknown")
        sig_id = str(alert.get("signature_id", ""))
        severity_raw = alert.get("severity", 3)
        # Suricata severity: 1=high, 3=low (same as Snort priority)
        severity = _PRIORITY_TO_SEVERITY.get(int(severity_raw), 5)
        classification = alert.get("category", "unknown")

        src_ip = data.get("src_ip")
        dst_ip = data.get("dest_ip")
        src_port = data.get("src_port")
        dst_port = data.get("dest_port")
        proto = (data.get("proto") or "").lower() or None

        return _ids_event(
            ts=ts, hostname=hostname, raw=raw,
            sig_name=sig_name, sig_id=sig_id,
            classification=classification, priority=int(severity_raw),
            src_ip=src_ip, src_port=src_port, dst_ip=dst_ip, dst_port=dst_port,
            protocol=proto, severity=severity,
            msg=f"Suricata alert: {sig_name}",
        )


def _ids_event(
    ts: datetime,
    hostname: Optional[str],
    raw: str,
    sig_name: str,
    sig_id: str = "",
    classification: str = "unknown",
    priority: int = 3,
    src_ip: Optional[str] = None,
    src_port: Optional[int] = None,
    dst_ip: Optional[str] = None,
    dst_port: Optional[int] = None,
    protocol: Optional[str] = None,
    severity: int = 5,
    msg: str = "",
) -> ParsedEvent:
    labels: dict = {
        "signature_name": sig_name,
        "classification": classification,
        "priority": str(priority),
    }
    if sig_id:
        labels["signature_id"] = sig_id

    return ParsedEvent(
        timestamp=ts,
        dataset="unifi.ids_ips",
        event_kind="alert",
        event_category=["intrusion_detection"],
        event_type=["denied"],
        event_severity=severity,
        event_outcome="failure",
        source_ip=src_ip,
        source_port=src_port,
        dest_ip=dst_ip,
        dest_port=dst_port,
        network_protocol=protocol,
        hostname=hostname,
        observer_type="ids",
        tags=["ids", "ips", "alert"],
        labels=labels,
        message=msg or f"IDS alert: {sig_name}",
        raw_message=raw,
    )
