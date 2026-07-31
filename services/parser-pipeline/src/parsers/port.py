"""Parser for switch port / STP / VLAN event log entries."""
from __future__ import annotations

import re
from datetime import datetime
from typing import Optional

from .base import BaseParser, ParsedEvent

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

# swconfig: port N link [up|down] speed=1000M duplex=full
_SWCONFIG_LINK = re.compile(
    r"(?:swconfig|switch).*?port\s+(?P<port>\d+)\s+link\s+(?P<state>up|down)"
    r"(?:.*?speed=(?P<speed>\w+))?(?:.*?duplex=(?P<duplex>\w+))?",
    re.IGNORECASE,
)

# Generic port link state
_PORT_LINK = re.compile(
    r"(?:Port|port)\s+(?P<port>\S+)\s+(?:link\s+)?(?P<state>(?:came\s+)?(?:up|down|connected|disconnected))",
    re.IGNORECASE,
)

# STP: port N on <bridge> entering FORWARDING state
_STP_STATE = re.compile(
    r"port\s+(?P<port>\d+)\s+on\s+(?P<bridge>\S+)\s+entering\s+(?P<state>\w+)\s+state",
    re.IGNORECASE,
)

# STP topology change
_STP_TOPO = re.compile(
    r"topology change\s+(?:detected|sent|received)?.*?(?:on\s+(?P<bridge>\S+))?",
    re.IGNORECASE,
)

# STP BPDU guard
_STP_BPDU = re.compile(
    r"BPDU\s+(?:guard|Guard)\s+(?:triggered|activated).*?(?:port\s+(?P<port>\S+))?",
    re.IGNORECASE,
)

# VLAN change
_VLAN_CHANGE = re.compile(
    r"(?:VLAN|vlan)\s+(?P<vid>\d+)\s+(?P<action>added|removed|changed|created|deleted)"
    r"(?:.*?(?:on\s+(?:port\s+)?(?P<port>\S+)))?",
    re.IGNORECASE,
)

# Port security violation: MAC flapping / unauthorized MAC
_PORT_SECURITY = re.compile(
    r"(?:security\s+violation|MAC\s+flap(?:ping)?|unauthorized\s+MAC)"
    r".*?(?:port\s+(?P<port>\S+))?(?:.*?MAC\s+(?P<mac>[\da-f:]{17}))?",
    re.IGNORECASE,
)

# MAC flapping specifically: port X MAC aa:bb:cc:dd:ee:ff moved from portA to portB
_MAC_FLAP = re.compile(
    r"MAC\s+(?P<mac>[\da-f:]{17})\s+(?:moved|flapped|flapping)\s+from\s+(?P<from_port>\S+)\s+to\s+(?P<to_port>\S+)",
    re.IGNORECASE,
)

# EtherChannel / LACP: port-channel status
_LACP = re.compile(
    r"LACP.*?(?:port-channel\s+(?P<pc>\S+))?.*?(?:member\s+(?P<port>\S+))?.*?(?P<state>up|down|attached|detached)",
    re.IGNORECASE,
)

# PoE events
_POE = re.compile(
    r"PoE.*?port\s+(?P<port>\S+).*?(?P<state>powered|off|overload|fault)",
    re.IGNORECASE,
)

_PORT_PROGRAMS = frozenset({
    "swconfig", "switch", "brctl", "bridge", "mstpd", "rstp",
    "stp", "dot1x", "lacp",
})
_PORT_KEYWORDS = re.compile(
    r"swconfig.*port\s+\d+\s+link"
    r"|port\s+\d+\s+on\s+\S+\s+entering\s+\w+\s+state"
    r"|topology change\s+(?:detected|sent)"
    r"|BPDU\s+guard\s+(?:triggered|activated)"
    r"|VLAN\s+\d+\s+(?:added|removed|changed)"
    r"|security violation|MAC\s+flap"
    r"|PoE.*port.*(?:powered|overload)",
    re.IGNORECASE,
)


class PortParser(BaseParser):
    """Parse switch port, STP, VLAN, and port security event log entries."""

    def can_parse(self, raw: str, program: Optional[str], hostname: Optional[str]) -> bool:
        prog_match = program and program.lower().split("[")[0] in _PORT_PROGRAMS
        kw_match = bool(_PORT_KEYWORDS.search(raw))
        return bool(prog_match and kw_match) or bool(kw_match)

    def parse(self, raw: str, source_ip: str, received_at: datetime) -> Optional[ParsedEvent]:
        try:
            return self._parse(raw, source_ip, received_at)
        except Exception:
            return None

    def _parse(self, raw: str, source_ip: str, received_at: datetime) -> Optional[ParsedEvent]:
        ts, hostname, program, msg = self._extract_syslog_header(raw)
        ts = ts or received_at

        # MAC flap (high priority security event)
        m = _MAC_FLAP.search(raw)
        if m:
            return _port_event(ts, hostname, raw, "mac_flap",
                               port=m.group("to_port"),
                               labels={"mac": m.group("mac"),
                                       "from_port": m.group("from_port"),
                                       "to_port": m.group("to_port")},
                               msg=f"MAC flap: {m.group('mac')} {m.group('from_port')} -> {m.group('to_port')}",
                               severity=7)

        # Port security violation
        m = _PORT_SECURITY.search(raw)
        if m:
            port = m.group("port") if m.lastindex and m.lastindex >= 1 else None
            mac = m.group("mac") if m.lastindex and m.lastindex >= 2 else None
            labels = {}
            if port:
                labels["port"] = port
            if mac:
                labels["violating_mac"] = mac
            return _port_event(ts, hostname, raw, "security_violation",
                               port=port, labels=labels,
                               msg=f"Port security violation on {port or 'unknown'}"
                                   + (f" MAC {mac}" if mac else ""),
                               severity=8)

        # BPDU guard
        m = _STP_BPDU.search(raw)
        if m:
            port = m.group("port") if m.lastindex and m.lastindex >= 1 else None
            return _port_event(ts, hostname, raw, "bpdu_guard",
                               port=port,
                               msg=f"BPDU guard triggered" + (f" on port {port}" if port else ""),
                               severity=7)

        # STP topology change
        if _STP_TOPO.search(raw):
            m = _STP_TOPO.search(raw)
            bridge = m.group("bridge") if m and m.lastindex and m.lastindex >= 1 else None
            return _port_event(ts, hostname, raw, "stp_topology_change",
                               labels={"bridge": bridge or ""},
                               msg=f"STP topology change" + (f" on {bridge}" if bridge else ""),
                               severity=5)

        # STP state change
        m = _STP_STATE.search(raw)
        if m:
            return _port_event(ts, hostname, raw, "stp_state_change",
                               port=m.group("port"),
                               labels={"bridge": m.group("bridge"), "stp_state": m.group("state")},
                               msg=f"STP port {m.group('port')} on {m.group('bridge')} -> {m.group('state')}")

        # swconfig link
        m = _SWCONFIG_LINK.search(raw)
        if m:
            state = m.group("state").lower()
            speed = m.group("speed") or ""
            duplex = m.group("duplex") or ""
            return _port_event(ts, hostname, raw, f"port_link_{state}",
                               port=m.group("port"),
                               labels={"speed": speed, "duplex": duplex},
                               ev_type=["start"] if state == "up" else ["end"],
                               msg=f"Port {m.group('port')} link {state}"
                                   + (f" {speed} {duplex}" if speed else ""))

        # Generic port link
        m = _PORT_LINK.search(raw)
        if m:
            state_raw = m.group("state").lower().replace("came ", "")
            return _port_event(ts, hostname, raw, f"port_link_{state_raw}",
                               port=m.group("port"),
                               ev_type=["start"] if "up" in state_raw or "connect" in state_raw else ["end"],
                               msg=f"Port {m.group('port')} {state_raw}")

        # VLAN change
        m = _VLAN_CHANGE.search(raw)
        if m:
            return _port_event(ts, hostname, raw, f"vlan_{m.group('action').lower()}",
                               port=m.group("port"),
                               labels={"vlan_id": m.group("vid"), "vlan_action": m.group("action").lower()},
                               msg=f"VLAN {m.group('vid')} {m.group('action').lower()}"
                                   + (f" on port {m.group('port')}" if m.group("port") else ""))

        # PoE
        m = _POE.search(raw)
        if m:
            state = m.group("state").lower()
            severity = 6 if state in ("overload", "fault") else 2
            return _port_event(ts, hostname, raw, f"poe_{state}",
                               port=m.group("port"),
                               msg=f"PoE port {m.group('port')} {state}", severity=severity)

        return None


def _port_event(
    ts: datetime,
    hostname: Optional[str],
    raw: str,
    event_type_name: str,
    port: Optional[str] = None,
    labels: Optional[dict] = None,
    ev_type: Optional[list] = None,
    msg: str = "",
    severity: int = 3,
) -> ParsedEvent:
    lbl: dict = {"port_event": event_type_name}
    if port:
        lbl["port_id"] = str(port)
    if labels:
        lbl.update(labels)
    return ParsedEvent(
        timestamp=ts,
        dataset="unifi.port",
        event_kind="event",
        event_category=["network"],
        event_type=ev_type or ["info"],
        event_severity=severity,
        event_outcome="success",
        hostname=hostname,
        observer_type="switch",
        tags=["port", "switch"],
        labels=lbl,
        message=msg,
        raw_message=raw,
    )
