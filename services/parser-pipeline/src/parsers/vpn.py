"""Parser for VPN log entries (OpenVPN, StrongSwan/IPsec, L2TP)."""
from __future__ import annotations

import re
from datetime import datetime
from typing import Optional

from .base import BaseParser, ParsedEvent

# ---------------------------------------------------------------------------
# OpenVPN patterns
# ---------------------------------------------------------------------------
# OpenVPN: <COMMON_NAME>/<ip>:<port> CONNECTED or DISCONNECTED
_OVPN_CONNECTED = re.compile(
    r"(?P<user>\S+)/(?P<ip>[\d.]+):(?P<port>\d+)\s+(?:MULTI_sva:|CONNECTED|client connected)",
    re.IGNORECASE,
)
_OVPN_DISCONNECTED = re.compile(
    r"(?P<user>\S+)/(?P<ip>[\d.]+):(?P<port>\d+)\s+(?:DISCONNECTED|client disconnected|Connection reset)",
    re.IGNORECASE,
)
# OpenVPN: TLS: Initial packet from [AF_INET]<ip>:<port>
_OVPN_TLS_INIT = re.compile(
    r"TLS: Initial packet from \[AF_INET\](?P<ip>[\d.]+):(?P<port>\d+)",
)
# OpenVPN: TLS Error, AUTH_FAILED
_OVPN_AUTH_FAILED = re.compile(
    r"(?:TLS Error|AUTH_FAILED|AUTH failed).*?(?:from \[AF_INET\](?P<ip>[\d.]+):(?P<port>\d+))?",
    re.IGNORECASE,
)
# OpenVPN: Peer Connection Initiated with [AF_INET]<ip>:<port>
_OVPN_PEER = re.compile(
    r"Peer Connection Initiated with \[AF_INET\](?P<ip>[\d.]+):(?P<port>\d+)",
)

# ---------------------------------------------------------------------------
# StrongSwan / IPsec patterns
# ---------------------------------------------------------------------------
# charon: connection 'conn_name' established successfully between <local>[<local_ip>]...<peer_ip>
_CHARON_ESTABLISHED = re.compile(
    r"connection '(?P<tunnel>\S+)' established successfully",
    re.IGNORECASE,
)
# charon: IKE_SA conn[N] established with <ip>
_CHARON_IKE_UP = re.compile(
    r"IKE_SA\s+\S+\[[\d]+\]\s+established\s+between\s+[\d.]+\[.*?\]\.\.\.\s*(?P<ip>[\d.]+)",
)
# charon: connection terminated by peer
_CHARON_TERM = re.compile(
    r"(?:connection '(?P<tunnel>\S+)' terminated|IKE_SA\s+\S+.*?deleted)",
    re.IGNORECASE,
)
# ipsec: AUTH_FAILED or authentication failure
_IPSEC_AUTH_FAILED = re.compile(
    r"(?:AUTH_FAILED|authentication.*failed|IKE authentication.*failed).*?(?:from\s+(?P<ip>[\d.]+))?",
    re.IGNORECASE,
)
# ipsec: peer IP
_IPSEC_PEER = re.compile(r"(?:peer|from)\s+(?P<ip>[\d.]+(?:\[\d+\])?)", re.IGNORECASE)

# ---------------------------------------------------------------------------
# L2TP patterns
# ---------------------------------------------------------------------------
_L2TP_TUNNEL_UP = re.compile(
    r"L2TP tunnel (?P<tid>\S+) (?:established|up).*?(?:peer=(?P<ip>[\d.]+))?",
    re.IGNORECASE,
)
_L2TP_TUNNEL_DOWN = re.compile(
    r"L2TP tunnel (?P<tid>\S+) (?:closed|down|destroyed)",
    re.IGNORECASE,
)
_PPTPD_CONNECTED = re.compile(
    r"pptpd.*?(?:connection from|CTRL:) (?P<ip>[\d.]+)",
    re.IGNORECASE,
)
_PPTPD_DISCONNECTED = re.compile(
    r"pptpd.*?(?:END|DISC|client (?P<ip>[\d.]+) disconnected)",
    re.IGNORECASE,
)

_VPN_PROGRAMS = frozenset({"openvpn", "charon", "ipsec", "pluto", "xl2tpd", "l2tpd", "pptpd", "strongswan"})
_VPN_KEYWORDS = re.compile(
    r"openvpn|CONNECTED.*VPN|VPN.*DISCONNECTED|TLS: Initial packet"
    r"|IKE_SA.*established|ipsec.*established|L2TP tunnel"
    r"|AUTH_FAILED|pptpd|xl2tpd|charon",
    re.IGNORECASE,
)


class VPNParser(BaseParser):
    """Parse VPN log events: OpenVPN, StrongSwan/IPsec, L2TP/PPTP."""

    def can_parse(self, raw: str, program: Optional[str], hostname: Optional[str]) -> bool:
        prog_match = program and program.lower().split("[")[0] in _VPN_PROGRAMS
        kw_match = bool(_VPN_KEYWORDS.search(raw))
        return bool(prog_match or kw_match)

    def parse(self, raw: str, source_ip: str, received_at: datetime) -> Optional[ParsedEvent]:
        try:
            return self._parse(raw, source_ip, received_at)
        except Exception:
            return None

    def _parse(self, raw: str, source_ip: str, received_at: datetime) -> Optional[ParsedEvent]:
        ts, hostname, program, msg = self._extract_syslog_header(raw)
        ts = ts or received_at

        # OpenVPN connected
        m = _OVPN_CONNECTED.search(raw)
        if m:
            return _vpn_event(ts, hostname, raw, "openvpn",
                              username=m.group("user"), peer_ip=m.group("ip"),
                              peer_port=self._safe_int(m.group("port")),
                              event_type=["start"], outcome="success",
                              msg=f"OpenVPN client {m.group('user')} connected from {m.group('ip')}")

        # OpenVPN disconnected
        m = _OVPN_DISCONNECTED.search(raw)
        if m:
            return _vpn_event(ts, hostname, raw, "openvpn",
                              username=m.group("user"), peer_ip=m.group("ip"),
                              peer_port=self._safe_int(m.group("port")),
                              event_type=["end"], outcome="success",
                              msg=f"OpenVPN client {m.group('user')} disconnected from {m.group('ip')}")

        # OpenVPN TLS init
        m = _OVPN_TLS_INIT.search(raw)
        if m:
            return _vpn_event(ts, hostname, raw, "openvpn",
                              peer_ip=m.group("ip"), peer_port=self._safe_int(m.group("port")),
                              event_type=["info"], outcome="unknown",
                              msg=f"OpenVPN TLS handshake from {m.group('ip')}")

        # OpenVPN auth failed
        m = _OVPN_AUTH_FAILED.search(raw)
        if m and re.search(r"AUTH_FAILED|TLS Error", raw, re.IGNORECASE):
            ip = m.group("ip") if m.lastindex else None
            return _vpn_event(ts, hostname, raw, "openvpn",
                              peer_ip=ip, event_type=["denied"], outcome="failure",
                              msg="OpenVPN authentication failed", severity=7)

        # OpenVPN peer connection
        m = _OVPN_PEER.search(raw)
        if m and "openvpn" in raw.lower():
            return _vpn_event(ts, hostname, raw, "openvpn",
                              peer_ip=m.group("ip"), peer_port=self._safe_int(m.group("port")),
                              event_type=["info"], outcome="unknown",
                              msg=f"OpenVPN peer connection from {m.group('ip')}")

        # StrongSwan established
        m = _CHARON_ESTABLISHED.search(raw)
        if m:
            peer_ip = None
            mp = _IPSEC_PEER.search(raw)
            if mp:
                peer_ip = mp.group("ip").split("[")[0]
            return _vpn_event(ts, hostname, raw, "ipsec",
                              tunnel_id=m.group("tunnel"), peer_ip=peer_ip,
                              event_type=["start"], outcome="success",
                              msg=f"IPsec tunnel {m.group('tunnel')} established")

        # StrongSwan IKE up
        m = _CHARON_IKE_UP.search(raw)
        if m:
            return _vpn_event(ts, hostname, raw, "ipsec",
                              peer_ip=m.group("ip"),
                              event_type=["start"], outcome="success",
                              msg=f"IPsec IKE_SA established with {m.group('ip')}")

        # StrongSwan terminated
        m = _CHARON_TERM.search(raw)
        if m:
            tunnel = m.group("tunnel") if "tunnel" in m.groupdict() else None
            return _vpn_event(ts, hostname, raw, "ipsec",
                              tunnel_id=tunnel,
                              event_type=["end"], outcome="success",
                              msg=f"IPsec tunnel {tunnel or 'unknown'} terminated")

        # IPsec auth failed
        m = _IPSEC_AUTH_FAILED.search(raw)
        if m and re.search(r"AUTH_FAILED|authentication.*failed", raw, re.IGNORECASE):
            ip = m.group("ip") if m.lastindex and m.lastindex >= 1 else None
            return _vpn_event(ts, hostname, raw, "ipsec",
                              peer_ip=ip, event_type=["denied"], outcome="failure",
                              msg="IPsec authentication failed", severity=7)

        # L2TP tunnel up
        m = _L2TP_TUNNEL_UP.search(raw)
        if m:
            ip = m.group("ip") if m.lastindex and m.lastindex >= 2 else None
            return _vpn_event(ts, hostname, raw, "l2tp",
                              tunnel_id=m.group("tid"), peer_ip=ip,
                              event_type=["start"], outcome="success",
                              msg=f"L2TP tunnel {m.group('tid')} established")

        # L2TP tunnel down
        m = _L2TP_TUNNEL_DOWN.search(raw)
        if m:
            return _vpn_event(ts, hostname, raw, "l2tp",
                              tunnel_id=m.group("tid"),
                              event_type=["end"], outcome="success",
                              msg=f"L2TP tunnel {m.group('tid')} closed")

        # PPTP connected
        m = _PPTPD_CONNECTED.search(raw)
        if m:
            return _vpn_event(ts, hostname, raw, "pptp",
                              peer_ip=m.group("ip"),
                              event_type=["start"], outcome="success",
                              msg=f"PPTP connection from {m.group('ip')}")

        return None


def _vpn_event(
    ts: datetime,
    hostname: Optional[str],
    raw: str,
    protocol: str,
    username: Optional[str] = None,
    peer_ip: Optional[str] = None,
    peer_port: Optional[int] = None,
    tunnel_id: Optional[str] = None,
    event_type: Optional[list] = None,
    outcome: str = "unknown",
    msg: str = "",
    severity: int = 4,
) -> ParsedEvent:
    labels: dict = {"vpn_protocol": protocol}
    if tunnel_id:
        labels["tunnel_id"] = tunnel_id
    return ParsedEvent(
        timestamp=ts,
        dataset="unifi.vpn",
        event_kind="event",
        event_category=["session", "network"],
        event_type=event_type or ["info"],
        event_severity=severity,
        event_outcome=outcome,
        source_ip=peer_ip,
        source_port=peer_port,
        hostname=hostname,
        username=username,
        network_protocol=protocol,
        observer_type="firewall",
        tags=["vpn", protocol],
        labels=labels,
        message=msg,
        raw_message=raw,
    )
