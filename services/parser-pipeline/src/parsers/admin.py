"""Parser for UniFi admin / management activity log entries."""
from __future__ import annotations

import re
from datetime import datetime
from typing import Optional

from .base import BaseParser, ParsedEvent

# ---------------------------------------------------------------------------
# UniFi Network Application (mcad / ubnt-util) patterns
# ---------------------------------------------------------------------------

# mcad: admin login: user=admin from 192.168.1.10
_MCAD_LOGIN = re.compile(
    r"(?:admin|user)\s+(?:login|logged in)[:\s]+(?:user=)?(?P<user>\S+).*?from\s+(?P<ip>[\d.]+)",
    re.IGNORECASE,
)

# mcad: admin logout
_MCAD_LOGOUT = re.compile(
    r"(?:admin|user)\s+(?:logout|logged out)[:\s]+(?:user=)?(?P<user>\S+)",
    re.IGNORECASE,
)

# mcad: settings changed by admin
_MCAD_SETTINGS = re.compile(
    r"settings?\s+changed?\s+(?:by\s+)?(?P<user>\S+)(?:.*?at\s+(?P<ip>[\d.]+))?",
    re.IGNORECASE,
)

# mcad: device provisioned: <device_name> (<mac>)
_MCAD_PROVISION = re.compile(
    r"(?:device\s+)?(?:provisiond?|adopted?)\s+(?P<device>[^(]+?)\s*\((?P<mac>[\da-f:]+)\)",
    re.IGNORECASE,
)

# ubnt-util: Admin login succeeded/failed for <user> from <ip>
_UBNT_LOGIN_SUCCESS = re.compile(
    r"Admin login (?:succeeded|successful)[:\s]+(?:for\s+)?(?P<user>\S+).*?from\s+(?P<ip>[\d.]+)",
    re.IGNORECASE,
)
_UBNT_LOGIN_FAILED = re.compile(
    r"Admin login (?:failed|failure)[:\s]+(?:for\s+)?(?P<user>\S+).*?from\s+(?P<ip>[\d.]+)",
    re.IGNORECASE,
)

# Configuration change: <key> changed from <old> to <new>
_CONFIG_CHANGE = re.compile(
    r"(?P<key>\S+)\s+changed\s+from\s+(?P<old>\S+)\s+to\s+(?P<new>\S+)",
    re.IGNORECASE,
)

# Device state: <mac> state changed to <state>
_DEVICE_STATE = re.compile(
    r"(?P<mac>[\da-f:]{17})\s+state\s+changed\s+to\s+(?P<state>\S+)",
    re.IGNORECASE,
)

# GUI access: GET/POST /api/... from <ip>
_API_ACCESS = re.compile(
    r"(?:GET|POST|PUT|DELETE|PATCH)\s+/api/\S+.*?from\s+(?P<ip>[\d.]+)",
    re.IGNORECASE,
)

# Firmware upgrade initiated
_FW_UPGRADE = re.compile(
    r"(?:firmware\s+)?upgrade\s+(?:initiated|started|completed).*?(?:on\s+)?(?P<device>\S+)?",
    re.IGNORECASE,
)

_ADMIN_PROGRAMS = frozenset({
    "mcad", "ubnt-util", "unifi", "unifi-network", "ubnt-admin",
    "unifi-core", "unifi-protect", "network-application",
})
_ADMIN_KEYWORDS = re.compile(
    r"admin\s+login|Admin login|user\s+logged\s+(?:in|out)|settings?\s+changed"
    r"|device\s+provisi|device\s+adopted|firmware\s+upgrade"
    r"|ubnt-util|mcad:",
    re.IGNORECASE,
)


class AdminParser(BaseParser):
    """Parse UniFi admin and management activity log entries."""

    def can_parse(self, raw: str, program: Optional[str], hostname: Optional[str]) -> bool:
        prog_match = program and program.lower().split("[")[0] in _ADMIN_PROGRAMS
        kw_match = bool(_ADMIN_KEYWORDS.search(raw))
        return bool(prog_match and kw_match) or bool(kw_match and prog_match)

    def parse(self, raw: str, source_ip: str, received_at: datetime) -> Optional[ParsedEvent]:
        try:
            return self._parse(raw, source_ip, received_at)
        except Exception:
            return None

    def _parse(self, raw: str, source_ip: str, received_at: datetime) -> Optional[ParsedEvent]:
        ts, hostname, program, msg = self._extract_syslog_header(raw)
        ts = ts or received_at

        # Admin login succeeded
        m = _UBNT_LOGIN_SUCCESS.search(raw)
        if m:
            return _admin_event(ts, hostname, raw,
                                action="login",
                                admin_user=m.group("user"), src_ip=m.group("ip"),
                                success=True,
                                msg=f"Admin login succeeded for {m.group('user')} from {m.group('ip')}")

        # Admin login failed
        m = _UBNT_LOGIN_FAILED.search(raw)
        if m:
            return _admin_event(ts, hostname, raw,
                                action="login_failed",
                                admin_user=m.group("user"), src_ip=m.group("ip"),
                                success=False,
                                msg=f"Admin login failed for {m.group('user')} from {m.group('ip')}",
                                severity=7)

        # mcad login
        m = _MCAD_LOGIN.search(raw)
        if m:
            return _admin_event(ts, hostname, raw,
                                action="login",
                                admin_user=m.group("user"), src_ip=m.group("ip"),
                                success=True,
                                msg=f"Admin login: {m.group('user')} from {m.group('ip')}")

        # mcad logout
        m = _MCAD_LOGOUT.search(raw)
        if m:
            return _admin_event(ts, hostname, raw,
                                action="logout",
                                admin_user=m.group("user"),
                                msg=f"Admin logout: {m.group('user')}")

        # Settings changed
        m = _MCAD_SETTINGS.search(raw)
        if m:
            ip = m.group("ip") if m.lastindex and m.lastindex >= 2 else None
            return _admin_event(ts, hostname, raw,
                                action="settings_change",
                                admin_user=m.group("user"), src_ip=ip,
                                msg=f"Settings changed by {m.group('user')}",
                                severity=5)

        # Device provisioned/adopted
        m = _MCAD_PROVISION.search(raw)
        if m:
            device = m.group("device").strip()
            mac = m.group("mac")
            return _admin_event(ts, hostname, raw,
                                action="provision",
                                labels={"device": device, "device_mac": mac},
                                msg=f"Device provisioned: {device} ({mac})")

        # Config change
        m = _CONFIG_CHANGE.search(raw)
        if m:
            return _admin_event(ts, hostname, raw,
                                action="config_change",
                                labels={"config_key": m.group("key"),
                                        "old_value": m.group("old")[:64],
                                        "new_value": m.group("new")[:64]},
                                msg=f"Config {m.group('key')} changed: {m.group('old')} -> {m.group('new')}")

        # Firmware upgrade
        m = _FW_UPGRADE.search(raw)
        if m:
            device = m.group("device") or "unknown"
            return _admin_event(ts, hostname, raw,
                                action="firmware_upgrade",
                                labels={"target_device": device},
                                msg=f"Firmware upgrade on {device}",
                                severity=4)

        return None


def _admin_event(
    ts: datetime,
    hostname: Optional[str],
    raw: str,
    action: str,
    admin_user: Optional[str] = None,
    src_ip: Optional[str] = None,
    success: bool = True,
    msg: str = "",
    severity: int = 4,
    labels: Optional[dict] = None,
) -> ParsedEvent:
    lbl = {"admin_action": action}
    if labels:
        lbl.update(labels)
    outcome = "success" if success else "failure"
    ev_type = ["info"] if success else ["denied"]
    return ParsedEvent(
        timestamp=ts,
        dataset="unifi.admin",
        event_kind="event",
        event_category=["authentication", "configuration"],
        event_type=ev_type,
        event_severity=severity,
        event_outcome=outcome,
        source_ip=src_ip,
        hostname=hostname,
        username=admin_user,
        observer_type="firewall",
        tags=["admin"],
        labels=lbl,
        message=msg,
        raw_message=raw,
    )
