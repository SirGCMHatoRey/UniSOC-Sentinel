"""Parser for UniFi device adoption / provisioning event log entries."""
from __future__ import annotations

import re
from datetime import datetime
from typing import Optional

from .base import BaseParser, ParsedEvent

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

# ubnt-discovery: device adopted: MAC aa:bb:cc:dd:ee:ff IP 192.168.1.10 model UAP-AC-Pro
_UBNT_ADOPTED = re.compile(
    r"(?:device\s+adopted|ubnt.*adopted).*?"
    r"(?:MAC\s+)?(?P<mac>[\da-f:]{17}).*?"
    r"(?:IP\s+(?P<ip>[\d.]+))?.*?"
    r"(?:model\s+(?P<model>[A-Z0-9\-]+))?",
    re.IGNORECASE,
)

# ubnt-discovery: device provisioned
_UBNT_PROVISIONED = re.compile(
    r"(?:device\s+provisioned|ubnt.*provisioned).*?"
    r"(?:MAC\s+)?(?P<mac>[\da-f:]{17}).*?"
    r"(?:IP\s+(?P<ip>[\d.]+))?",
    re.IGNORECASE,
)

# ubnt: device forgot/forgotten
_UBNT_FORGOT = re.compile(
    r"(?:device\s+(?:forgot|forgotten|removed|deleted)).*?"
    r"(?:MAC\s+)?(?P<mac>[\da-f:]{17})?",
    re.IGNORECASE,
)

# UniFi device state: aa:bb:cc:dd:ee:ff state changed to connected/disconnected/isolated
_DEVICE_STATE = re.compile(
    r"(?P<mac>[\da-f:]{17})\s+(?:state\s+changed\s+to|is\s+now)\s+(?P<state>\S+)",
    re.IGNORECASE,
)

# Device upgrade: device aa:bb:cc:dd:ee:ff upgraded to firmware X.Y.Z
_DEVICE_UPGRADE = re.compile(
    r"device\s+(?P<mac>[\da-f:]{17})\s+upgraded.*?firmware\s+(?P<fw>[\d.]+)",
    re.IGNORECASE,
)

# Device restarted/rebooted
_DEVICE_REBOOT = re.compile(
    r"device\s+(?P<mac>[\da-f:]{17})\s+(?:rebooted|restarted|reset)",
    re.IGNORECASE,
)

# Discovery: new device detected
_UBNT_DISCOVERED = re.compile(
    r"(?:discovered|new device detected).*?"
    r"(?:MAC\s+)?(?P<mac>[\da-f:]{17}).*?"
    r"(?:IP\s+(?P<ip>[\d.]+))?.*?"
    r"(?:model\s+(?P<model>[A-Z0-9\-]+))?",
    re.IGNORECASE,
)

# SSH connection from UniFi controller to device
_CTRL_SSH = re.compile(
    r"SSH.*?(?:to|from)\s+(?P<ip>[\d.]+).*?(?:MAC\s+)?(?P<mac>[\da-f:]{17})?",
    re.IGNORECASE,
)

# License seat assigned
_LICENSE = re.compile(
    r"license\s+(?:assigned|revoked).*?(?:to\s+(?P<mac>[\da-f:]{17}))?",
    re.IGNORECASE,
)

_DEVICE_PROGRAMS = frozenset({
    "ubnt-discovery", "ubnt", "unifi-device", "ubnt-util",
    "unifi-network", "unifi-core",
})
_DEVICE_KEYWORDS = re.compile(
    r"device\s+(?:adopted|provisioned|forgot|discovered)"
    r"|ubnt.*(?:adopted|provisioned)"
    r"|(?:state\s+changed\s+to|is\s+now)\s+(?:connected|disconnected|isolated)"
    r"|device.*upgraded.*firmware"
    r"|device.*rebooted",
    re.IGNORECASE,
)


class DeviceParser(BaseParser):
    """Parse UniFi device adoption, provisioning, and state change events."""

    def can_parse(self, raw: str, program: Optional[str], hostname: Optional[str]) -> bool:
        prog_match = program and program.lower().split("[")[0] in _DEVICE_PROGRAMS
        kw_match = bool(_DEVICE_KEYWORDS.search(raw))
        return bool(prog_match and kw_match) or bool(kw_match and prog_match)

    def parse(self, raw: str, source_ip: str, received_at: datetime) -> Optional[ParsedEvent]:
        try:
            return self._parse(raw, source_ip, received_at)
        except Exception:
            return None

    def _parse(self, raw: str, source_ip: str, received_at: datetime) -> Optional[ParsedEvent]:
        ts, hostname, program, msg = self._extract_syslog_header(raw)
        ts = ts or received_at

        # Device adopted
        m = _UBNT_ADOPTED.search(raw)
        if m and "adopt" in raw.lower():
            return _device_event(ts, hostname, raw, "adopted",
                                 mac=m.group("mac"), ip=m.group("ip"),
                                 model=m.group("model"),
                                 msg=f"Device adopted: {m.group('mac')}"
                                     + (f" ({m.group('model')})" if m.group("model") else ""))

        # Device discovered
        m = _UBNT_DISCOVERED.search(raw)
        if m and "discover" in raw.lower():
            return _device_event(ts, hostname, raw, "discovered",
                                 mac=m.group("mac"), ip=m.group("ip"),
                                 model=m.group("model"),
                                 msg=f"Device discovered: {m.group('mac')}"
                                     + (f" ({m.group('model')})" if m.group("model") else ""))

        # Device provisioned
        m = _UBNT_PROVISIONED.search(raw)
        if m:
            return _device_event(ts, hostname, raw, "provisioned",
                                 mac=m.group("mac"), ip=m.group("ip"),
                                 msg=f"Device provisioned: {m.group('mac')}")

        # Device forgotten
        m = _UBNT_FORGOT.search(raw)
        if m:
            mac = m.group("mac") if m.lastindex and m.lastindex >= 1 else None
            return _device_event(ts, hostname, raw, "forgot",
                                 mac=mac,
                                 msg=f"Device forgotten: {mac or 'unknown'}", severity=5)

        # Device firmware upgrade
        m = _DEVICE_UPGRADE.search(raw)
        if m:
            return _device_event(ts, hostname, raw, "firmware_upgrade",
                                 mac=m.group("mac"),
                                 labels={"firmware_version": m.group("fw")},
                                 msg=f"Device {m.group('mac')} upgraded to firmware {m.group('fw')}")

        # Device reboot
        m = _DEVICE_REBOOT.search(raw)
        if m:
            return _device_event(ts, hostname, raw, "reboot",
                                 mac=m.group("mac"),
                                 msg=f"Device {m.group('mac')} rebooted", severity=5)

        # Device state changed
        m = _DEVICE_STATE.search(raw)
        if m:
            state = m.group("state").lower()
            sev = 5 if state in ("disconnected", "isolated") else 3
            return _device_event(ts, hostname, raw, f"state_{state}",
                                 mac=m.group("mac"),
                                 labels={"device_state": state},
                                 msg=f"Device {m.group('mac')} state -> {state}", severity=sev)

        return None


def _device_event(
    ts: datetime,
    hostname: Optional[str],
    raw: str,
    action: str,
    mac: Optional[str] = None,
    ip: Optional[str] = None,
    model: Optional[str] = None,
    labels: Optional[dict] = None,
    msg: str = "",
    severity: int = 4,
) -> ParsedEvent:
    lbl: dict = {"device_action": action}
    if mac:
        lbl["device_mac"] = mac
    if ip:
        lbl["device_ip"] = ip
    if model:
        lbl["device_model"] = model
    if labels:
        lbl.update(labels)
    return ParsedEvent(
        timestamp=ts,
        dataset="unifi.device",
        event_kind="event",
        event_category=["configuration"],
        event_type=["info"],
        event_severity=severity,
        event_outcome="success",
        source_ip=ip,
        source_mac=mac,
        hostname=hostname,
        observer_type="firewall",
        tags=["device", "unifi"],
        labels=lbl,
        message=msg,
        raw_message=raw,
    )
