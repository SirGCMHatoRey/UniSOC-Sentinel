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


def build_default_registry() -> ParserRegistry:
    """
    Build and return the default parser registry with all 15 parsers registered
    in priority order (most specific / high-signal first).
    """
    registry = ParserRegistry()

    # 1. IDS/IPS — very specific signatures, check early to avoid FP with firewall
    registry.register(IDSIPSParser())

    # 2. Threat management — ubnt-specific threat blocking keywords
    registry.register(ThreatParser())

    # 3. Firewall — iptables/UFW/ACL rules; very common, must follow IDS
    registry.register(FirewallParser())

    # 4. Auth — SSH/PAM authentication events
    registry.register(AuthParser())

    # 5. VPN — OpenVPN / StrongSwan / L2TP
    registry.register(VPNParser())

    # 6. Wireless — hostapd 802.11 events
    registry.register(WirelessParser())

    # 7. DHCP — dnsmasq DHCP messages (very distinctive keywords)
    registry.register(DHCPParser())

    # 8. DNS — dnsmasq query/reply messages
    registry.register(DNSParser())

    # 9. Traffic — connection tracking / netflow
    registry.register(TrafficParser())

    # 10. WAN — PPPoE / DHCP WAN / link events on WAN interfaces
    registry.register(WANParser())

    # 11. Port — switch port / STP / VLAN events
    registry.register(PortParser())

    # 12. Device — UniFi device adoption / provisioning
    registry.register(DeviceParser())

    # 13. Admin — UniFi admin login / settings change
    registry.register(AdminParser())

    # 14. System — kernel OOM / service events (broad; near end to avoid FP)
    registry.register(SystemParser())

    return registry
