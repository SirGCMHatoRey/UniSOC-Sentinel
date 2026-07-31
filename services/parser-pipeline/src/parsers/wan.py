"""Parser for WAN interface event log entries."""
from __future__ import annotations

import re
from datetime import datetime
from typing import Optional

from .base import BaseParser, ParsedEvent

# ---------------------------------------------------------------------------
# PPPoE patterns
# ---------------------------------------------------------------------------
# pppd: Connect: ppp0 <--> /dev/ttyS0
_PPPOE_CONNECT = re.compile(
    r"(?:Connect|Connected):\s+(?P<iface>ppp\d+)\s+<-->",
    re.IGNORECASE,
)

# pppd: local IP address 1.2.3.4 / remote IP address 5.6.7.8
_PPPOE_IP = re.compile(
    r"local\s+IP\s+address\s+(?P<local>[\d.]+).*?remote\s+IP\s+address\s+(?P<remote>[\d.]+)",
    re.IGNORECASE,
)

# pppd: Modem hangup / Connection terminated / LCP down
_PPPOE_DISCONNECT = re.compile(
    r"(?:Modem hangup|LCP terminated|Connection terminated|pppd.*down|LCP: timeout)",
    re.IGNORECASE,
)

# pppd: PAP / CHAP authentication succeeded/failed
_PPP_AUTH_OK = re.compile(r"(?:PAP|CHAP)\s+authentication\s+succeeded", re.IGNORECASE)
_PPP_AUTH_FAIL = re.compile(r"(?:PAP|CHAP)\s+authentication\s+failed", re.IGNORECASE)

# ---------------------------------------------------------------------------
# DHCP WAN patterns
# ---------------------------------------------------------------------------
# dhclient: bound to 1.2.3.4 -- renewal in N seconds
_DHCP_WAN_BOUND = re.compile(
    r"bound to\s+(?P<ip>[\d.]+)\s+--\s+(?:renewal|rebind)(?:\s+in\s+(?P<sec>\d+)\s+seconds)?",
    re.IGNORECASE,
)

# dhclient: DHCPACK of 1.2.3.4 from 5.6.7.8
_DHCP_WAN_ACK = re.compile(
    r"DHCPACK of\s+(?P<ip>[\d.]+) from\s+(?P<gw>[\d.]+)",
    re.IGNORECASE,
)

# dhclient: No DHCPOFFERS received
_DHCP_WAN_FAIL = re.compile(r"No\s+DHCPOFFERS\s+received", re.IGNORECASE)

# ---------------------------------------------------------------------------
# IP address change
# ---------------------------------------------------------------------------
# ip: <iface>: <new_ip>/<prefix>
_IP_CHANGE = re.compile(
    r"(?P<iface>eth\d+|ppp\d+|wan\d*)\s+IP\s+(?:address\s+)?(?:changed\s+to\s+)?(?P<ip>[\d.]+)",
    re.IGNORECASE,
)

# Link up/down on WAN
_WAN_LINK_UP = re.compile(
    r"(?P<iface>eth\d+|ppp\d+|wan\d*):\s+Link\s+(?:is\s+)?(?P<state>[Uu]p|[Dd]own)"
    r"(?:\s+(?P<speed>\d+\w+))?",
)

# Gateway changed
_GW_CHANGE = re.compile(
    r"(?:default\s+)?gateway(?:\s+changed)?\s+(?:to\s+)?(?P<gw>[\d.]+)",
    re.IGNORECASE,
)

# WAN failover
_WAN_FAILOVER = re.compile(
    r"WAN\s+(?:failover|fail-over|failback).*?(?:to\s+(?P<iface>\S+))?",
    re.IGNORECASE,
)

_WAN_PROGRAMS = frozenset({
    "pppd", "pppoe", "dhclient", "udhcpc", "networkd", "ifup", "ifdown",
    "wan-monitor", "ubnt-wan",
})
_WAN_KEYWORDS = re.compile(
    r"Connect:\s+ppp\d+|LCP terminated|Modem hangup|PPPoE"
    r"|bound to [\d.]+\s+--\s+renewal"
    r"|DHCPACK of [\d.]+ from"
    r"|No DHCPOFFERS received"
    r"|(?:eth\d|ppp\d|wan).*Link is (?:Up|Down)"
    r"|WAN failover|WAN fail-over"
    r"|local IP address [\d.]+",
    re.IGNORECASE,
)


class WANParser(BaseParser):
    """Parse WAN interface events: PPPoE, DHCP, link state, IP change."""

    def can_parse(self, raw: str, program: Optional[str], hostname: Optional[str]) -> bool:
        prog_match = program and program.lower().split("[")[0] in _WAN_PROGRAMS
        kw_match = bool(_WAN_KEYWORDS.search(raw))
        return bool(prog_match and kw_match) or bool(kw_match)

    def parse(self, raw: str, source_ip: str, received_at: datetime) -> Optional[ParsedEvent]:
        try:
            return self._parse(raw, source_ip, received_at)
        except Exception:
            return None

    def _parse(self, raw: str, source_ip: str, received_at: datetime) -> Optional[ParsedEvent]:
        ts, hostname, program, msg = self._extract_syslog_header(raw)
        ts = ts or received_at

        # PPPoE connected
        m = _PPPOE_CONNECT.search(raw)
        if m:
            iface = m.group("iface")
            # Try to extract IP from same log block
            m_ip = _PPPOE_IP.search(raw)
            ip = m_ip.group("local") if m_ip else None
            return _wan_event(ts, hostname, raw, "pppoe_connect", iface=iface, ip=ip,
                              ev_type=["start"],
                              msg=f"PPPoE connected on {iface}" + (f" ({ip})" if ip else ""))

        # PPPoE IP assignment
        m = _PPPOE_IP.search(raw)
        if m:
            return _wan_event(ts, hostname, raw, "pppoe_ip", ip=m.group("local"),
                              gateway=m.group("remote"),
                              msg=f"PPPoE IP: {m.group('local')} gateway {m.group('remote')}")

        # PPPoE disconnected
        if _PPPOE_DISCONNECT.search(raw):
            return _wan_event(ts, hostname, raw, "pppoe_disconnect",
                              ev_type=["end"],
                              msg="PPPoE connection terminated")

        # PPP auth success
        if _PPP_AUTH_OK.search(raw):
            return _wan_event(ts, hostname, raw, "ppp_auth_success",
                              msg="PPP authentication succeeded")

        # PPP auth failure
        if _PPP_AUTH_FAIL.search(raw):
            return _wan_event(ts, hostname, raw, "ppp_auth_failure",
                              outcome="failure", ev_type=["denied"], severity=6,
                              msg="PPP authentication failed")

        # DHCP WAN bound
        m = _DHCP_WAN_BOUND.search(raw)
        if m:
            return _wan_event(ts, hostname, raw, "dhcp_bound", ip=m.group("ip"),
                              ev_type=["start"],
                              labels={"renewal_sec": m.group("sec") or ""},
                              msg=f"WAN DHCP bound to {m.group('ip')}")

        # DHCP WAN ACK
        m = _DHCP_WAN_ACK.search(raw)
        if m:
            return _wan_event(ts, hostname, raw, "dhcp_ack", ip=m.group("ip"),
                              gateway=m.group("gw"),
                              msg=f"WAN DHCP ACK: {m.group('ip')} from {m.group('gw')}")

        # DHCP WAN failure
        if _DHCP_WAN_FAIL.search(raw):
            return _wan_event(ts, hostname, raw, "dhcp_failure",
                              outcome="failure", ev_type=["denied"], severity=6,
                              msg="WAN DHCP: no offers received")

        # WAN link up/down
        m = _WAN_LINK_UP.search(raw)
        if m:
            state = m.group("state").lower()
            speed = m.group("speed") if m.lastindex and m.lastindex >= 3 else None
            labels = {}
            if speed:
                labels["speed"] = speed
            return _wan_event(ts, hostname, raw, f"link_{state}", iface=m.group("iface"),
                              ev_type=["start"] if state == "up" else ["end"],
                              labels=labels,
                              msg=f"WAN {m.group('iface')} link {state}"
                                  + (f" @ {speed}" if speed else ""))

        # WAN failover
        m = _WAN_FAILOVER.search(raw)
        if m:
            to_iface = m.group("iface") if m.lastindex and m.lastindex >= 1 else None
            return _wan_event(ts, hostname, raw, "wan_failover",
                              iface=to_iface,
                              msg=f"WAN failover" + (f" to {to_iface}" if to_iface else ""),
                              severity=6)

        # Gateway change
        m = _GW_CHANGE.search(raw)
        if m:
            return _wan_event(ts, hostname, raw, "gateway_change",
                              gateway=m.group("gw"),
                              msg=f"Default gateway changed to {m.group('gw')}")

        return None


def _wan_event(
    ts: datetime,
    hostname: Optional[str],
    raw: str,
    event_type_name: str,
    iface: Optional[str] = None,
    ip: Optional[str] = None,
    gateway: Optional[str] = None,
    ev_type: Optional[list] = None,
    outcome: str = "success",
    severity: int = 4,
    labels: Optional[dict] = None,
    msg: str = "",
) -> ParsedEvent:
    lbl: dict = {"wan_event": event_type_name}
    if iface:
        lbl["interface"] = iface
    if gateway:
        lbl["gateway"] = gateway
    if labels:
        lbl.update(labels)
    return ParsedEvent(
        timestamp=ts,
        dataset="unifi.wan",
        event_kind="event",
        event_category=["network"],
        event_type=ev_type or ["info"],
        event_severity=severity,
        event_outcome=outcome,
        source_ip=ip,
        hostname=hostname,
        network_protocol="pppoe" if "pppoe" in event_type_name else None,
        observer_type="firewall",
        tags=["wan", "network"],
        labels=lbl,
        message=msg,
        raw_message=raw,
    )
