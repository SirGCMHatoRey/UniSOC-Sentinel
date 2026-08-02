"""
Tests for the parser registry precedence structure
(services/parser-pipeline/src/parsers/registry.py).

Seams under test:
  - The module-level priority structure (`_PARSER_PRIORITY`) that expresses
    parser classification precedence as data.
  - `build_default_registry()` — builds a `ParserRegistry` from that structure.
  - `ParserRegistry.find_parser()` — first-match-wins dispatch, exercised with
    representative log lines to prove the refactor did not change which
    parser wins for overlapping input (issue #7 acceptance criteria).
"""

from __future__ import annotations

from src.parsers.admin import AdminParser
from src.parsers.auth import AuthParser
from src.parsers.base import BaseParser
from src.parsers.device import DeviceParser
from src.parsers.dhcp import DHCPParser
from src.parsers.dns import DNSParser
from src.parsers.firewall import FirewallParser
from src.parsers.ids_ips import IDSIPSParser
from src.parsers.port import PortParser
from src.parsers.registry import _PARSER_PRIORITY, ParserRegistry, build_default_registry
from src.parsers.system import SystemParser
from src.parsers.threat import ThreatParser
from src.parsers.traffic import TrafficParser
from src.parsers.vpn import VPNParser
from src.parsers.wan import WANParser
from src.parsers.wireless import WirelessParser

# The exact original registration order (from the pre-refactor hardcoded
# sequence of `registry.register(...)` calls in build_default_registry()).
_EXPECTED_ORDER: list[type[BaseParser]] = [
    IDSIPSParser,
    ThreatParser,
    FirewallParser,
    AuthParser,
    VPNParser,
    WirelessParser,
    DHCPParser,
    DNSParser,
    TrafficParser,
    WANParser,
    PortParser,
    DeviceParser,
    AdminParser,
    SystemParser,
]


def test_parser_priority_structure_lists_all_parsers_with_reasons() -> None:
    """
    _PARSER_PRIORITY is a single, inspectable structure containing all 14
    parsers, each paired with a non-empty reason string explaining its
    position. Reading this one structure answers "why does parser A run
    before parser B" without reading each parser's can_parse().
    """
    assert len(_PARSER_PRIORITY) == 14

    for entry in _PARSER_PRIORITY:
        parser_cls, reason = entry
        assert isinstance(parser_cls, type)
        assert issubclass(parser_cls, BaseParser)
        assert isinstance(reason, str)
        assert reason.strip() != ""

    # Every parser class appears exactly once.
    classes = [entry[0] for entry in _PARSER_PRIORITY]
    assert len(classes) == len(set(classes))


def test_build_default_registry_preserves_original_registration_order() -> None:
    """
    build_default_registry() must produce a ParserRegistry whose internal
    parser order is byte-for-byte the same sequence as the original
    hardcoded 14-call registration (IDS/IPS first ... System last).
    Precedence is re-expressed as data, not reordered.
    """
    registry = build_default_registry()

    assert repr(registry) == f"ParserRegistry({[cls.__name__ for cls in _EXPECTED_ORDER]})"

    # Cross-check the priority structure itself drives that same order.
    assert [entry[0] for entry in _PARSER_PRIORITY] == _EXPECTED_ORDER


def test_firewall_line_resolves_to_firewall_parser() -> None:
    """
    A UFW-style firewall block line — should be classified by FirewallParser.
    Confirmed via firewall.py: `_FIREWALL_KEYWORDS` matches
    "[UFW BLOCK]" directly (`\\[UFW\\s+(?:BLOCK|ALLOW|LIMIT|FORWARD)\\]`).
    Neither ThreatParser's `_THREAT_KEYWORDS` nor IDSIPSParser's
    `_IDS_KEYWORDS` match this line, so this is a clean baseline case.
    """
    raw = (
        "<134>Jan  1 00:00:01 gateway kernel: [UFW BLOCK] IN=eth0 OUT= "
        "MAC=aa:bb:cc:dd:ee:ff SRC=203.0.113.5 DST=192.168.1.10 "
        "PROTO=TCP SPT=54321 DPT=443 LEN=60"
    )
    registry = build_default_registry()

    parser = registry.find_parser(raw, program=None, hostname=None)

    assert isinstance(parser, FirewallParser)


def test_threat_line_overlapping_firewall_resolves_to_threat_parser() -> None:
    """
    Regression test for the exact precedence issue #7 is about: a line that
    genuinely satisfies BOTH ThreatParser.can_parse() and
    FirewallParser.can_parse() must still resolve to ThreatParser, because
    ThreatParser is registered before FirewallParser ("ubnt-specific threat
    blocking keywords" ... "must follow IDS" applies transitively: threat
    must also win over firewall, matching the original call order).

    Confirmed by reading both files:
      - threat.py `_THREAT_KEYWORDS` matches on the literal substring
        "ubnt-threat-management".
      - firewall.py `_FIREWALL_KEYWORDS` matches `kernel:.*?SRC=[\\d.]`
        (a "kernel:" token anywhere before a "SRC=<digit>" token, re.IGNORECASE).
    The line below contains "kernel:" followed later by "SRC=203.0.113.5",
    so it matches _FIREWALL_KEYWORDS, AND contains "ubnt-threat-management",
    so it matches _THREAT_KEYWORDS too — genuine overlap.
    """
    raw = (
        "<134>Jan  1 00:00:02 gateway kernel: ubnt-threat-management BLOCK "
        "SRC=203.0.113.5 DST=192.168.1.10 threat=Mirai.Botnet"
    )
    registry = build_default_registry()

    # Confirm the overlap actually exists before asserting precedence.
    assert ThreatParser().can_parse(raw, None, None) is True
    assert FirewallParser().can_parse(raw, None, None) is True

    parser = registry.find_parser(raw, program=None, hostname=None)

    assert isinstance(parser, ThreatParser)


def test_ids_line_overlapping_firewall_resolves_to_ids_parser() -> None:
    """
    A Snort-style IDS alert that also overlaps FirewallParser's keyword
    pattern must resolve to IDSIPSParser — this is the "very specific
    signatures, check early to avoid FP with firewall" precedence from the
    original comment.

    Confirmed by reading both files:
      - ids_ips.py `_IDS_KEYWORDS` matches `\\[\\*\\*\\].*\\[\\*\\*\\]` (the
        Snort "[**] ... [**]" bracket pair) and `\\[Classification:`.
      - firewall.py `_FIREWALL_KEYWORDS` matches `kernel:.*?SRC=[\\d.]`.
    The line below has a "kernel:" program tag ahead of a Snort alert body
    that also carries an "SRC=<ip>" token, so both parsers' can_parse()
    return True — genuine overlap.
    """
    raw = (
        "<134>Jan  1 00:00:03 gateway kernel: snort: [**] [1:2100498:7] "
        "GPL ATTACK_RESPONSE id check returned root [**] "
        "[Classification: Potentially Bad Traffic] [Priority: 2] "
        "{TCP} SRC=203.0.113.5 DST=192.168.1.10"
    )
    registry = build_default_registry()

    # Confirm the overlap actually exists before asserting precedence.
    assert IDSIPSParser().can_parse(raw, None, None) is True
    assert FirewallParser().can_parse(raw, None, None) is True

    parser = registry.find_parser(raw, program=None, hostname=None)

    assert isinstance(parser, IDSIPSParser)
