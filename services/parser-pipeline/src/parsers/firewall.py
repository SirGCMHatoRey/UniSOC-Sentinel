"""Parser for UniFi firewall / iptables log lines."""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Optional

from .base import BaseParser, ParsedEvent

# ---------------------------------------------------------------------------
# Pattern: UFW-style  "[UFW BLOCK] IN=eth0 OUT= MAC=... SRC=1.2.3.4 DST=..."
# ---------------------------------------------------------------------------
_UFW_RE = re.compile(
    r"\[UFW\s+(?P<action>BLOCK|ALLOW|LIMIT|FORWARD)\]"
    r"(?:.*?IN=(?P<in_if>\S*))?(?:.*?OUT=(?P<out_if>\S*))?(?:.*?MAC=(?P<mac>[\da-f:]+))?"
    r"(?:.*?SRC=(?P<src>[\d.]+))?(?:.*?DST=(?P<dst>[\d.]+))?"
    r"(?:.*?PROTO=(?P<proto>\S+))?(?:.*?SPT=(?P<spt>\d+))?(?:.*?DPT=(?P<dpt>\d+))?"
    r"(?:.*?LEN=(?P<len>\d+))?",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Pattern: ACL-style  "[ACL-WAN-LOCAL-D-4]" or "[WAN_LOCAL-D]"
# ---------------------------------------------------------------------------
_ACL_HEADER_RE = re.compile(
    r"\[(?P<acl>[A-Z0-9_\-]+-(?P<verdict>[DA])-\d*)\]",
    re.IGNORECASE,
)

# Generic iptables kv pairs
_KV_RE = re.compile(
    r"(?:IN=(?P<in_if>\S*)|OUT=(?P<out_if>\S*)|MAC=(?P<mac>[\da-fA-F:]+)"
    r"|SRC=(?P<src>[\d.]+)|DST=(?P<dst>[\d.]+)"
    r"|PROTO=(?P<proto>\S+)|SPT=(?P<spt>\d+)|DPT=(?P<dpt>\d+)"
    r"|LEN=(?P<len>\d+)|TTL=(?P<ttl>\d+)|ID=(?P<id>\d+)"
    r"|WINDOW=(?P<window>\d+)|RES=(?P<res>\S+)|SYN|ACK|FIN|RST|URG|PSH"
    r"|TYPE=(?P<type>\d+)|CODE=(?P<code>\d+))"
)

# kernel: [BLOCK] / [DROP] / [ACCEPT]
_KERNEL_VERDICT_RE = re.compile(r"kernel:.*?\[(?P<verdict>BLOCK|DROP|ACCEPT|FORWARD)\]", re.IGNORECASE)

# UniFi-specific ACL format: "ACL-WAN-LOCAL-D" where D=deny, A=allow
_ACL_NAME_RE = re.compile(
    r"\[(?P<name>[A-Z]{2,10}-[A-Z]{2,10}-[A-Z]{2,10}-(?P<verdict>[DA])(?:-\d+)?)\]",
    re.IGNORECASE,
)

_FIREWALL_PROGRAMS = frozenset({"kernel", "ufw", "iptables", "ip6tables", "nftables"})
_FIREWALL_KEYWORDS = re.compile(
    r"\[UFW\s+(?:BLOCK|ALLOW|LIMIT|FORWARD)\]"
    r"|\[ACL-"
    r"|\[WAN_LOCAL"
    r"|\[WAN-LOCAL"
    r"|\[LAN_LOCAL"
    r"|\[FORWARD"
    r"|kernel:.*?SRC=[\d.]"
    r"|\[BLOCK\]|\[DROP\]|\[ACCEPT\]",
    re.IGNORECASE,
)


def _extract_kv(text: str) -> dict:
    """Extract all iptables key=value pairs from text."""
    result: dict = {}
    for m in _KV_RE.finditer(text):
        for k, v in m.groupdict().items():
            if v is not None and k not in result:
                result[k] = v
    return result


class FirewallParser(BaseParser):
    """Parse UniFi firewall / iptables log entries."""

    def can_parse(self, raw: str, program: Optional[str], hostname: Optional[str]) -> bool:
        prog_match = program and program.lower() in _FIREWALL_PROGRAMS
        kw_match = bool(_FIREWALL_KEYWORDS.search(raw))
        return bool(prog_match or kw_match)

    def parse(self, raw: str, source_ip: str, received_at: datetime) -> Optional[ParsedEvent]:
        try:
            return self._parse(raw, source_ip, received_at)
        except Exception:
            return None

    def _parse(self, raw: str, source_ip: str, received_at: datetime) -> Optional[ParsedEvent]:
        ts, hostname, program, msg = self._extract_syslog_header(raw)
        ts = ts or received_at

        action = "unknown"
        direction = "unknown"

        # Try UFW first
        m_ufw = _UFW_RE.search(raw)
        if m_ufw:
            action = m_ufw.group("action").lower()
            kv = _extract_kv(raw)
            in_if = m_ufw.group("in_if") or kv.get("in_if", "")
            out_if = m_ufw.group("out_if") or kv.get("out_if", "")
            direction = _infer_direction(in_if, out_if)
            return _build_event(
                ts=ts,
                hostname=hostname,
                action=action,
                direction=direction,
                kv=kv,
                raw=raw,
                src_override=m_ufw.group("src"),
                dst_override=m_ufw.group("dst"),
                proto_override=m_ufw.group("proto"),
                spt_override=m_ufw.group("spt"),
                dpt_override=m_ufw.group("dpt"),
                mac_override=m_ufw.group("mac"),
                len_override=m_ufw.group("len"),
            )

        # Try ACL-style header
        m_acl = _ACL_NAME_RE.search(raw) or _ACL_HEADER_RE.search(raw)
        if m_acl:
            verdict_char = m_acl.group("verdict").upper() if "verdict" in m_acl.groupdict() else "D"
            action = "allow" if verdict_char == "A" else "block"
            kv = _extract_kv(raw)
            in_if = kv.get("in_if", "")
            out_if = kv.get("out_if", "")
            direction = _infer_direction(in_if, out_if)
            return _build_event(
                ts=ts,
                hostname=hostname,
                action=action,
                direction=direction,
                kv=kv,
                raw=raw,
            )

        # Try generic kernel iptables with SRC= / DST=
        if re.search(r"SRC=[\d.]+", raw):
            kv = _extract_kv(raw)
            m_v = _KERNEL_VERDICT_RE.search(raw)
            if m_v:
                v = m_v.group("verdict").lower()
                action = "allow" if v in ("accept",) else "block"
            else:
                action = "block"  # default assume block for kernel fw logs
            in_if = kv.get("in_if", "")
            out_if = kv.get("out_if", "")
            direction = _infer_direction(in_if, out_if)
            return _build_event(
                ts=ts,
                hostname=hostname,
                action=action,
                direction=direction,
                kv=kv,
                raw=raw,
            )

        return None


def _infer_direction(in_if: str, out_if: str) -> str:
    in_if = (in_if or "").lower()
    out_if = (out_if or "").lower()
    wan_prefixes = ("eth0", "eth1", "ppp", "wan")
    lan_prefixes = ("br", "eth2", "eth3", "eth4", "lan", "vlan")

    def is_wan(iface: str) -> bool:
        return any(iface.startswith(p) for p in wan_prefixes)

    def is_lan(iface: str) -> bool:
        return any(iface.startswith(p) for p in lan_prefixes)

    if in_if and out_if:
        if is_wan(in_if) and is_lan(out_if):
            return "inbound"
        if is_lan(in_if) and is_wan(out_if):
            return "outbound"
        if is_lan(in_if) and is_lan(out_if):
            return "internal"
    elif in_if and is_wan(in_if):
        return "inbound"
    elif out_if and is_wan(out_if):
        return "outbound"
    return "unknown"


def _build_event(
    ts: datetime,
    hostname: Optional[str],
    action: str,
    direction: str,
    kv: dict,
    raw: str,
    src_override: Optional[str] = None,
    dst_override: Optional[str] = None,
    proto_override: Optional[str] = None,
    spt_override: Optional[str] = None,
    dpt_override: Optional[str] = None,
    mac_override: Optional[str] = None,
    len_override: Optional[str] = None,
) -> ParsedEvent:
    src_ip = src_override or kv.get("src")
    dst_ip = dst_override or kv.get("dst")
    proto = (proto_override or kv.get("proto", "")).lower() or None
    spt = _safe_int(spt_override or kv.get("spt"))
    dpt = _safe_int(dpt_override or kv.get("dpt"))
    pkt_len = _safe_int(len_override or kv.get("len"))
    mac = mac_override or kv.get("mac")

    is_blocked = action in ("block", "drop", "deny")
    event_type = ["denied"] if is_blocked else ["allowed"]
    outcome = "failure" if is_blocked else "success"
    severity = 7 if is_blocked else 3

    summary = (
        f"Firewall {'blocked' if is_blocked else 'allowed'} "
        f"{proto or 'traffic'} {src_ip or '?'}"
        f":{spt or '?'} -> {dst_ip or '?'}:{dpt or '?'}"
    )

    return ParsedEvent(
        timestamp=ts,
        dataset="unifi.firewall",
        event_kind="event",
        event_category=["network"],
        event_type=event_type,
        event_severity=severity,
        event_outcome=outcome,
        source_ip=src_ip,
        source_port=spt or None,
        source_mac=mac,
        dest_ip=dst_ip,
        dest_port=dpt or None,
        network_protocol=proto,
        network_direction=direction,
        network_bytes=pkt_len,
        network_packets=1 if pkt_len else 0,
        hostname=hostname,
        observer_type="firewall",
        tags=["firewall"],
        message=summary,
        raw_message=raw,
    )


def _safe_int(val: Optional[str], default: int = 0) -> int:
    if val is None:
        return default
    try:
        return int(val)
    except (ValueError, TypeError):
        return default
