"""Parser registry — discovers and dispatches to the right parser."""
from __future__ import annotations

from typing import Optional

from .base import BaseParser
from .firewall import FirewallParser
from .ids_ips import IDSIPSParser
from .threat import ThreatParser
from .auth import AuthParser
from .vpn import VPNParser
from .wireless import WirelessParser
from .dhcp import DHCPParser
from .dns import DNSParser
from .traffic import TrafficParser
from .wan import WANParser
from .port import PortParser
from .device import DeviceParser
from .admin import AdminParser
from .system import SystemParser


class ParserRegistry:
    """Ordered list of parsers; first match wins."""

    def __init__(self) -> None:
        self._parsers: list[BaseParser] = []

    def register(self, parser: BaseParser) -> None:
        """Append a parser to the registry (order matters)."""
        self._parsers.append(parser)

    def find_parser(
        self, raw: str, program: Optional[str], hostname: Optional[str]
    ) -> Optional[BaseParser]:
        """Return the first parser that claims it can handle this log line."""
        for p in self._parsers:
            try:
                if p.can_parse(raw, program, hostname):
                    return p
            except Exception:
                continue
        return None

    def __len__(self) -> int:
        return len(self._parsers)

    def __repr__(self) -> str:
        return f"ParserRegistry({[type(p).__name__ for p in self._parsers]})"


# ---------------------------------------------------------------------------
# Parser classification precedence.
#
# This is the single source of truth for parser registration order. When two
# parsers' `can_parse()` checks overlap on the same input, the one listed
# first here wins. Adding a new parser means adding an entry here — its
# position (and the reason for that position) must be stated explicitly;
# there is no other place ordering is decided.
# ---------------------------------------------------------------------------
_PARSER_PRIORITY: list[tuple[type[BaseParser], str]] = [
    (IDSIPSParser, "very specific signatures, check early to avoid FP with firewall"),
    (ThreatParser, "ubnt-specific threat blocking keywords"),
    (FirewallParser, "iptables/UFW/ACL rules; very common, must follow IDS"),
    (AuthParser, "SSH/PAM authentication events"),
    (VPNParser, "OpenVPN / StrongSwan / L2TP"),
    (WirelessParser, "hostapd 802.11 events"),
    (DHCPParser, "dnsmasq DHCP messages (very distinctive keywords)"),
    (DNSParser, "dnsmasq query/reply messages"),
    (TrafficParser, "connection tracking / netflow"),
    (WANParser, "PPPoE / DHCP WAN / link events on WAN interfaces"),
    (PortParser, "switch port / STP / VLAN events"),
    (DeviceParser, "UniFi device adoption / provisioning"),
    (AdminParser, "UniFi admin login / settings change"),
    (SystemParser, "kernel OOM / service events (broad; near end to avoid FP)"),
]


def build_default_registry() -> ParserRegistry:
    """
    Build and return the default parser registry with all 14 parsers registered
    in priority order (most specific / high-signal first), per _PARSER_PRIORITY.
    """
    registry = ParserRegistry()
    for parser_cls, _reason in _PARSER_PRIORITY:
        registry.register(parser_cls())
    return registry
