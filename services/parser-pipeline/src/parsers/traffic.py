"""Parser for traffic / connection tracking / flow log entries."""
from __future__ import annotations

import re
from datetime import datetime
from typing import Optional

from .base import BaseParser, ParsedEvent

# ---------------------------------------------------------------------------
# Netfilter connection tracking (conntrack)
# [NEW|ESTABLISHED|RELATED|DESTROYED] src=1.2.3.4 dst=5.6.7.8 sport=12345 dport=80 proto=TCP
# ---------------------------------------------------------------------------
_CONNTRACK = re.compile(
    r"(?P<state>NEW|ESTABLISHED|RELATED|DESTROYED|INVALID)\s+"
    r"(?:.*?src=(?P<src>[\d.]+))?(?:.*?dst=(?P<dst>[\d.]+))?"
    r"(?:.*?sport=(?P<spt>\d+))?(?:.*?dport=(?P<dpt>\d+))?"
    r"(?:.*?proto=(?P<proto>\w+))?(?:.*?bytes=(?P<bytes>\d+))?(?:.*?packets=(?P<pkts>\d+))?",
    re.IGNORECASE,
)

# Alternative conntrack: [UPDATE] tcp      6  431980 ESTABLISHED src=192.168.1.2 dst=...
_CONNTRACK_ALT = re.compile(
    r"\[(?P<state>[A-Z]+)\]\s+(?P<proto>\w+)\s+\d+\s+\d+\s+(?P<ct_state>\S+)\s+"
    r"src=(?P<src>[\d.]+)\s+dst=(?P<dst>[\d.]+)\s+sport=(?P<spt>\d+)\s+dport=(?P<dpt>\d+)"
    r".*?(?:bytes=(?P<bytes>\d+))?.*?(?:packets=(?P<pkts>\d+))?",
    re.IGNORECASE,
)

# UniFi traffic stats: ubnt-traffic src=1.2.3.4 dst=5.6.7.8 bytes=12345 pkts=100 dur=60
_UBNT_TRAFFIC = re.compile(
    r"(?:ubnt-traffic|traffic-stat|flow).*?"
    r"(?:src=(?P<src>[\d.]+))?(?:.*?dst=(?P<dst>[\d.]+))?"
    r"(?:.*?bytes=(?P<bytes>\d+))?(?:.*?pkts=(?P<pkts>\d+))?"
    r"(?:.*?dur(?:ation)?=(?P<dur>\d+))?(?:.*?proto=(?P<proto>\w+))?",
    re.IGNORECASE,
)

# Netflow-style: <src>:<sport> -> <dst>:<dport> [<proto>] <bytes> bytes <pkts> pkts
_NETFLOW_STYLE = re.compile(
    r"(?P<src>[\d.]+):(?P<spt>\d+)\s+->\s+(?P<dst>[\d.]+):(?P<dpt>\d+)"
    r"(?:\s+\[?(?P<proto>\w+)\]?)?"
    r"(?:\s+(?P<bytes>\d+)\s+bytes)?(?:\s+(?P<pkts>\d+)\s+(?:pkts|packets))?",
)

# TCP state transitions from connection tracking daemons
_TCP_STATE = re.compile(
    r"(?P<src>[\d.]+):(?P<spt>\d+)\s+(?P<dst>[\d.]+):(?P<dpt>\d+)\s+tcp\s+(?P<state>\w+)",
    re.IGNORECASE,
)

_TRAFFIC_PROGRAMS = frozenset({"conntrack", "ulogd", "netflow", "ubnt-traffic", "flow"})
_TRAFFIC_KEYWORDS = re.compile(
    r"\b(?:NEW|ESTABLISHED|RELATED|DESTROYED|INVALID)\b.*?(?:src=[\d.]|dst=[\d.])"
    r"|ubnt-traffic|netflow|bytes=\d+.*pkts=\d+"
    r"|\[UPDATE\]\s+(?:tcp|udp|icmp)",
    re.IGNORECASE,
)


class TrafficParser(BaseParser):
    """Parse connection tracking and flow log entries."""

    def can_parse(self, raw: str, program: Optional[str], hostname: Optional[str]) -> bool:
        prog_match = program and program.lower().split("[")[0] in _TRAFFIC_PROGRAMS
        kw_match = bool(_TRAFFIC_KEYWORDS.search(raw))
        return bool(prog_match or kw_match)

    def parse(self, raw: str, source_ip: str, received_at: datetime) -> Optional[ParsedEvent]:
        try:
            return self._parse(raw, source_ip, received_at)
        except Exception:
            return None

    def _parse(self, raw: str, source_ip: str, received_at: datetime) -> Optional[ParsedEvent]:
        ts, hostname, program, msg = self._extract_syslog_header(raw)
        ts = ts or received_at

        # Alternative conntrack format
        m = _CONNTRACK_ALT.search(raw)
        if m:
            state = m.group("state").upper()
            proto = m.group("proto").lower()
            ev_type = _state_to_event_type(state)
            return _traffic_event(
                ts=ts, hostname=hostname, raw=raw,
                src_ip=m.group("src"), src_port=self._safe_int(m.group("spt")),
                dst_ip=m.group("dst"), dst_port=self._safe_int(m.group("dpt")),
                proto=proto,
                net_bytes=self._safe_int(m.group("bytes")),
                net_pkts=self._safe_int(m.group("pkts")),
                ev_type=ev_type,
                labels={"conntrack_state": state, "ct_state": m.group("ct_state") or ""},
                msg=f"Connection {state.lower()} {proto} {m.group('src')}:{m.group('spt')} -> {m.group('dst')}:{m.group('dpt')}",
            )

        # Standard conntrack
        m = _CONNTRACK.search(raw)
        if m and (m.group("src") or m.group("dst")):
            state = (m.group("state") or "").upper()
            proto = (m.group("proto") or "").lower() or None
            ev_type = _state_to_event_type(state)
            return _traffic_event(
                ts=ts, hostname=hostname, raw=raw,
                src_ip=m.group("src"), src_port=self._safe_int(m.group("spt")),
                dst_ip=m.group("dst"), dst_port=self._safe_int(m.group("dpt")),
                proto=proto,
                net_bytes=self._safe_int(m.group("bytes")),
                net_pkts=self._safe_int(m.group("pkts")),
                ev_type=ev_type,
                labels={"conntrack_state": state},
                msg=f"Traffic {state.lower() or 'flow'}: {m.group('src') or '?'} -> {m.group('dst') or '?'}",
            )

        # ubnt-traffic
        m = _UBNT_TRAFFIC.search(raw)
        if m and (m.group("src") or m.group("dst")):
            return _traffic_event(
                ts=ts, hostname=hostname, raw=raw,
                src_ip=m.group("src"), dst_ip=m.group("dst"),
                proto=(m.group("proto") or "").lower() or None,
                net_bytes=self._safe_int(m.group("bytes")),
                net_pkts=self._safe_int(m.group("pkts")),
                msg=f"Traffic: {m.group('src') or '?'} -> {m.group('dst') or '?'} "
                    f"{m.group('bytes') or 0} bytes",
                labels={"duration_s": m.group("dur") or "0"},
            )

        # Netflow style
        m = _NETFLOW_STYLE.search(raw)
        if m:
            return _traffic_event(
                ts=ts, hostname=hostname, raw=raw,
                src_ip=m.group("src"), src_port=self._safe_int(m.group("spt")),
                dst_ip=m.group("dst"), dst_port=self._safe_int(m.group("dpt")),
                proto=(m.group("proto") or "").lower() or None,
                net_bytes=self._safe_int(m.group("bytes")),
                net_pkts=self._safe_int(m.group("pkts")),
                msg=f"Flow: {m.group('src')}:{m.group('spt')} -> {m.group('dst')}:{m.group('dpt')}",
            )

        return None


def _state_to_event_type(state: str) -> list:
    return {
        "NEW": ["start"],
        "ESTABLISHED": ["info"],
        "RELATED": ["info"],
        "DESTROYED": ["end"],
        "INVALID": ["denied"],
    }.get(state, ["info"])


def _traffic_event(
    ts: datetime,
    hostname: Optional[str],
    raw: str,
    src_ip: Optional[str] = None,
    src_port: Optional[int] = None,
    dst_ip: Optional[str] = None,
    dst_port: Optional[int] = None,
    proto: Optional[str] = None,
    net_bytes: int = 0,
    net_pkts: int = 0,
    ev_type: Optional[list] = None,
    msg: str = "",
    labels: Optional[dict] = None,
) -> ParsedEvent:
    lbl = labels or {}
    return ParsedEvent(
        timestamp=ts,
        dataset="unifi.traffic",
        event_kind="event",
        event_category=["network"],
        event_type=ev_type or ["info"],
        event_severity=1,
        event_outcome="success",
        source_ip=src_ip,
        source_port=src_port or None,
        dest_ip=dst_ip,
        dest_port=dst_port or None,
        network_protocol=proto,
        network_bytes=net_bytes,
        network_packets=net_pkts,
        hostname=hostname,
        observer_type="firewall",
        tags=["traffic", "flow"],
        labels=lbl,
        message=msg,
        raw_message=raw,
    )
