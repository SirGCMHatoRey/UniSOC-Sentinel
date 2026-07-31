"""Parser for DHCP log entries (dnsmasq-dhcp)."""
from __future__ import annotations

import re
from datetime import datetime
from typing import Optional

from .base import BaseParser, ParsedEvent

# ---------------------------------------------------------------------------
# dnsmasq-dhcp patterns
# ---------------------------------------------------------------------------

# DHCPACK(br0) 192.168.1.100 aa:bb:cc:dd:ee:ff hostname
_DNSMASQ_ACK = re.compile(
    r"DHCPACK\((?P<iface>[^)]+)\)\s+(?P<ip>[\d.]+)\s+(?P<mac>[\da-f:]+)(?:\s+(?P<host>\S+))?",
    re.IGNORECASE,
)

# DHCPREQUEST(br0) 192.168.1.100 aa:bb:cc:dd:ee:ff
_DNSMASQ_REQUEST = re.compile(
    r"DHCPREQUEST\((?P<iface>[^)]+)\)\s+(?P<ip>[\d.]+)\s+(?P<mac>[\da-f:]+)(?:\s+(?P<host>\S+))?",
    re.IGNORECASE,
)

# DHCPOFFER(br0) 192.168.1.100 aa:bb:cc:dd:ee:ff
_DNSMASQ_OFFER = re.compile(
    r"DHCPOFFER\((?P<iface>[^)]+)\)\s+(?P<ip>[\d.]+)\s+(?P<mac>[\da-f:]+)",
    re.IGNORECASE,
)

# DHCPDISCOVER(br0) aa:bb:cc:dd:ee:ff <hostname>
_DNSMASQ_DISCOVER = re.compile(
    r"DHCPDISCOVER\((?P<iface>[^)]+)\)\s+(?P<mac>[\da-f:]+)(?:\s+(?P<host>\S+))?",
    re.IGNORECASE,
)

# DHCPNAK(br0) 192.168.1.100 aa:bb:cc:dd:ee:ff
_DNSMASQ_NAK = re.compile(
    r"DHCPNAK\((?P<iface>[^)]+)\)\s+(?P<ip>[\d.]+)\s+(?P<mac>[\da-f:]+)",
    re.IGNORECASE,
)

# DHCPRELEASE(br0) 192.168.1.100 aa:bb:cc:dd:ee:ff <hostname>
_DNSMASQ_RELEASE = re.compile(
    r"DHCPRELEASE\((?P<iface>[^)]+)\)\s+(?P<ip>[\d.]+)\s+(?P<mac>[\da-f:]+)(?:\s+(?P<host>\S+))?",
    re.IGNORECASE,
)

# ISC DHCP server / udhcpd patterns
# DHCPACK on 192.168.1.100 to aa:bb:cc:dd:ee:ff (hostname) via eth0
_ISC_ACK = re.compile(
    r"DHCPACK on (?P<ip>[\d.]+) to (?P<mac>[\da-f:]+)(?:\s+\((?P<host>[^)]+)\))? via (?P<iface>\S+)",
    re.IGNORECASE,
)
_ISC_REQUEST = re.compile(
    r"DHCPREQUEST for (?P<ip>[\d.]+) from (?P<mac>[\da-f:]+)(?:\s+\((?P<host>[^)]+)\))? via (?P<iface>\S+)",
    re.IGNORECASE,
)
_ISC_RELEASE = re.compile(
    r"DHCPRELEASE of (?P<ip>[\d.]+) from (?P<mac>[\da-f:]+)(?:\s+\((?P<host>[^)]+)\))? via (?P<iface>\S+)",
    re.IGNORECASE,
)

_DHCP_PROGRAMS = frozenset({"dnsmasq", "dnsmasq-dhcp", "dhcpd", "udhcpd"})
_DHCP_KEYWORDS = re.compile(
    r"DHCPACK|DHCPREQUEST|DHCPOFFER|DHCPDISCOVER|DHCPNAK|DHCPRELEASE",
    re.IGNORECASE,
)


class DHCPParser(BaseParser):
    """Parse DHCP log entries from dnsmasq and ISC DHCP."""

    def can_parse(self, raw: str, program: Optional[str], hostname: Optional[str]) -> bool:
        prog_match = program and program.lower().split("[")[0] in _DHCP_PROGRAMS
        kw_match = bool(_DHCP_KEYWORDS.search(raw))
        return bool(kw_match)  # keyword alone is sufficient given DHCP msgs are distinctive

    def parse(self, raw: str, source_ip: str, received_at: datetime) -> Optional[ParsedEvent]:
        try:
            return self._parse(raw, source_ip, received_at)
        except Exception:
            return None

    def _parse(self, raw: str, source_ip: str, received_at: datetime) -> Optional[ParsedEvent]:
        ts, hostname, program, msg = self._extract_syslog_header(raw)
        ts = ts or received_at

        # dnsmasq DHCPACK
        m = _DNSMASQ_ACK.search(raw)
        if m:
            return _dhcp_event(ts, hostname, raw,
                               action="ack", assigned_ip=m.group("ip"),
                               client_mac=m.group("mac"), client_hostname=m.group("host"),
                               interface=m.group("iface"),
                               msg=f"DHCP ACK: {m.group('ip')} -> {m.group('mac')} ({m.group('host') or '?'})")

        # ISC DHCPACK
        m = _ISC_ACK.search(raw)
        if m:
            return _dhcp_event(ts, hostname, raw,
                               action="ack", assigned_ip=m.group("ip"),
                               client_mac=m.group("mac"), client_hostname=m.group("host"),
                               interface=m.group("iface"),
                               msg=f"DHCP ACK: {m.group('ip')} -> {m.group('mac')}")

        # dnsmasq DHCPREQUEST
        m = _DNSMASQ_REQUEST.search(raw)
        if m:
            return _dhcp_event(ts, hostname, raw,
                               action="request", assigned_ip=m.group("ip"),
                               client_mac=m.group("mac"), client_hostname=m.group("host"),
                               interface=m.group("iface"),
                               msg=f"DHCP REQUEST: {m.group('ip')} from {m.group('mac')}")

        # ISC DHCPREQUEST
        m = _ISC_REQUEST.search(raw)
        if m:
            return _dhcp_event(ts, hostname, raw,
                               action="request", assigned_ip=m.group("ip"),
                               client_mac=m.group("mac"), client_hostname=m.group("host"),
                               interface=m.group("iface"),
                               msg=f"DHCP REQUEST: {m.group('ip')} from {m.group('mac')}")

        # dnsmasq DHCPOFFER
        m = _DNSMASQ_OFFER.search(raw)
        if m:
            return _dhcp_event(ts, hostname, raw,
                               action="offer", assigned_ip=m.group("ip"),
                               client_mac=m.group("mac"), interface=m.group("iface"),
                               msg=f"DHCP OFFER: {m.group('ip')} to {m.group('mac')}")

        # dnsmasq DHCPDISCOVER
        m = _DNSMASQ_DISCOVER.search(raw)
        if m:
            return _dhcp_event(ts, hostname, raw,
                               action="discover", client_mac=m.group("mac"),
                               client_hostname=m.group("host"), interface=m.group("iface"),
                               msg=f"DHCP DISCOVER from {m.group('mac')}")

        # dnsmasq DHCPNAK
        m = _DNSMASQ_NAK.search(raw)
        if m:
            return _dhcp_event(ts, hostname, raw,
                               action="nak", assigned_ip=m.group("ip"),
                               client_mac=m.group("mac"), interface=m.group("iface"),
                               msg=f"DHCP NAK: {m.group('ip')} to {m.group('mac')}",
                               outcome="failure")

        # dnsmasq / ISC DHCPRELEASE
        m = _DNSMASQ_RELEASE.search(raw) or _ISC_RELEASE.search(raw)
        if m:
            return _dhcp_event(ts, hostname, raw,
                               action="release", assigned_ip=m.group("ip"),
                               client_mac=m.group("mac"), client_hostname=m.group("host"),
                               interface=m.group("iface"),
                               msg=f"DHCP RELEASE: {m.group('ip')} from {m.group('mac')}")

        return None


def _dhcp_event(
    ts: datetime,
    hostname: Optional[str],
    raw: str,
    action: str,
    assigned_ip: Optional[str] = None,
    client_mac: Optional[str] = None,
    client_hostname: Optional[str] = None,
    interface: Optional[str] = None,
    msg: str = "",
    outcome: str = "success",
) -> ParsedEvent:
    labels: dict = {"dhcp_action": action}
    if interface:
        labels["interface"] = interface
    if client_hostname:
        labels["client_hostname"] = client_hostname

    ev_type = ["info"]
    if action in ("ack",):
        ev_type = ["allowed"]
    elif action in ("nak",):
        ev_type = ["denied"]

    return ParsedEvent(
        timestamp=ts,
        dataset="unifi.dhcp",
        event_kind="event",
        event_category=["network"],
        event_type=ev_type,
        event_severity=2,
        event_outcome=outcome,
        source_ip=assigned_ip,
        source_mac=client_mac,
        hostname=hostname,
        observer_type="firewall",
        tags=["dhcp"],
        labels=labels,
        message=msg,
        raw_message=raw,
    )
