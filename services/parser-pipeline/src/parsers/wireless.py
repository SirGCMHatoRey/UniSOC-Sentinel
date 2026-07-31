"""Parser for wireless client event log entries (hostapd, 802.11)."""
from __future__ import annotations

import re
from datetime import datetime
from typing import Optional

from .base import BaseParser, ParsedEvent

# ---------------------------------------------------------------------------
# hostapd patterns
# ---------------------------------------------------------------------------

# hostapd: wlan0: STA aa:bb:cc:dd:ee:ff IEEE 802.11: authenticated
_HOSTAPD_AUTH = re.compile(
    r"(?P<iface>\S+):\s+STA\s+(?P<mac>[\da-f:]{17})\s+IEEE\s+802\.11:\s+authenticated",
    re.IGNORECASE,
)

# hostapd: wlan0: STA aa:bb:cc:dd:ee:ff IEEE 802.11: associated (aid N)
_HOSTAPD_ASSOC = re.compile(
    r"(?P<iface>\S+):\s+STA\s+(?P<mac>[\da-f:]{17})\s+IEEE\s+802\.11:\s+associated"
    r"(?:\s+\(aid\s+(?P<aid>\d+)\))?",
    re.IGNORECASE,
)

# hostapd: wlan0: STA aa:bb:cc:dd:ee:ff IEEE 802.11: disassociated
_HOSTAPD_DISASSOC = re.compile(
    r"(?P<iface>\S+):\s+STA\s+(?P<mac>[\da-f:]{17})\s+IEEE\s+802\.11:\s+disassociated",
    re.IGNORECASE,
)

# hostapd: wlan0: STA aa:bb:cc:dd:ee:ff IEEE 802.11: deauthenticated due to inactivity (idle for N seconds)
_HOSTAPD_DEAUTH = re.compile(
    r"(?P<iface>\S+):\s+STA\s+(?P<mac>[\da-f:]{17})\s+IEEE\s+802\.11:\s+deauthenticated"
    r"(?:\s+due to\s+(?P<reason>[^\(]+))?(?:\s*\(idle for\s+(?P<idle>\d+)\s+seconds\))?",
    re.IGNORECASE,
)

# hostapd: wlan0: STA aa:bb:cc:dd:ee:ff WPA: pairwise key handshake completed (RSN)
_HOSTAPD_WPA = re.compile(
    r"(?P<iface>\S+):\s+STA\s+(?P<mac>[\da-f:]{17})\s+WPA:\s+(?P<event>.+)",
    re.IGNORECASE,
)

# hostapd: STA aa:bb:cc:dd:ee:ff: RADIUS authentication failed
_HOSTAPD_RADIUS_FAIL = re.compile(
    r"STA\s+(?P<mac>[\da-f:]{17}):\s+RADIUS\s+authentication\s+(?P<outcome>failed|succeeded)",
    re.IGNORECASE,
)

# 802.11r FT: Roaming STA aa:bb:cc:dd:ee:ff from wlan0 to wlan1
_ROAM = re.compile(
    r"(?:FT|Roaming|roamed).*?STA\s+(?P<mac>[\da-f:]{17}).*?from\s+(?P<from_if>\S+).*?to\s+(?P<to_if>\S+)",
    re.IGNORECASE,
)

# Deauth reason codes
_REASON_CODE = re.compile(r"reason=(?P<code>\d+)", re.IGNORECASE)

# Signal strength in association
_SIGNAL = re.compile(r"signal=(?P<sig>-?\d+)\s*dBm", re.IGNORECASE)

# BSSID in log context
_BSSID = re.compile(r"BSSID[=:\s]+(?P<bssid>[\da-f:]{17})", re.IGNORECASE)

# SSID in log context
_SSID = re.compile(r"SSID[=:\s]+['\"]?(?P<ssid>[^'\"]+)['\"]?", re.IGNORECASE)

_WIRELESS_PROGRAMS = frozenset({"hostapd", "wpa_supplicant", "ath10k", "iwlwifi"})
_WIRELESS_KEYWORDS = re.compile(
    r"IEEE\s+802\.11:\s+(?:auth|assoc|disassoc|deauth)"
    r"|STA\s+[\da-f:]{17}\s+IEEE"
    r"|WPA:\s+pairwise key"
    r"|RADIUS\s+authentication",
    re.IGNORECASE,
)


class WirelessParser(BaseParser):
    """Parse wireless client event log entries from hostapd."""

    def can_parse(self, raw: str, program: Optional[str], hostname: Optional[str]) -> bool:
        prog_match = program and program.lower().split("[")[0] in _WIRELESS_PROGRAMS
        kw_match = bool(_WIRELESS_KEYWORDS.search(raw))
        return bool(kw_match)

    def parse(self, raw: str, source_ip: str, received_at: datetime) -> Optional[ParsedEvent]:
        try:
            return self._parse(raw, source_ip, received_at)
        except Exception:
            return None

    def _parse(self, raw: str, source_ip: str, received_at: datetime) -> Optional[ParsedEvent]:
        ts, hostname, program, msg = self._extract_syslog_header(raw)
        ts = ts or received_at

        # Extract common optional fields
        m_sig = _SIGNAL.search(raw)
        signal = m_sig.group("sig") if m_sig else None
        m_bss = _BSSID.search(raw)
        bssid = m_bss.group("bssid") if m_bss else None
        m_ssid = _SSID.search(raw)
        ssid = m_ssid.group("ssid").strip() if m_ssid else None
        m_reason = _REASON_CODE.search(raw)
        reason = m_reason.group("code") if m_reason else None

        # authenticated
        m = _HOSTAPD_AUTH.search(raw)
        if m:
            return _wifi_event(ts, hostname, raw,
                               action="authenticated",
                               client_mac=m.group("mac"), iface=m.group("iface"),
                               bssid=bssid, ssid=ssid, signal=signal,
                               ev_type=["start"], outcome="success",
                               msg=f"Wireless STA {m.group('mac')} authenticated on {m.group('iface')}")

        # associated
        m = _HOSTAPD_ASSOC.search(raw)
        if m:
            return _wifi_event(ts, hostname, raw,
                               action="associated",
                               client_mac=m.group("mac"), iface=m.group("iface"),
                               bssid=bssid, ssid=ssid, signal=signal,
                               ev_type=["start"], outcome="success",
                               msg=f"Wireless STA {m.group('mac')} associated on {m.group('iface')}")

        # disassociated
        m = _HOSTAPD_DISASSOC.search(raw)
        if m:
            return _wifi_event(ts, hostname, raw,
                               action="disassociated",
                               client_mac=m.group("mac"), iface=m.group("iface"),
                               reason_code=reason,
                               ev_type=["end"], outcome="success",
                               msg=f"Wireless STA {m.group('mac')} disassociated from {m.group('iface')}")

        # deauthenticated
        m = _HOSTAPD_DEAUTH.search(raw)
        if m:
            deauth_reason = m.group("reason").strip() if m.group("reason") else None
            return _wifi_event(ts, hostname, raw,
                               action="deauthenticated",
                               client_mac=m.group("mac"), iface=m.group("iface"),
                               reason_code=reason,
                               ev_type=["end"], outcome="success",
                               msg=f"Wireless STA {m.group('mac')} deauthenticated from {m.group('iface')}"
                                   + (f": {deauth_reason}" if deauth_reason else ""))

        # WPA key handshake
        m = _HOSTAPD_WPA.search(raw)
        if m:
            return _wifi_event(ts, hostname, raw,
                               action="wpa_handshake",
                               client_mac=m.group("mac"), iface=m.group("iface"),
                               ev_type=["info"], outcome="success",
                               msg=f"WPA: {m.group('event')} for {m.group('mac')}")

        # RADIUS auth result
        m = _HOSTAPD_RADIUS_FAIL.search(raw)
        if m:
            success = m.group("outcome").lower() == "succeeded"
            return _wifi_event(ts, hostname, raw,
                               action="radius_auth",
                               client_mac=m.group("mac"),
                               ev_type=["start" if success else "denied"],
                               outcome="success" if success else "failure",
                               msg=f"RADIUS authentication {m.group('outcome')} for {m.group('mac')}",
                               severity=3 if success else 7)

        # Roaming
        m = _ROAM.search(raw)
        if m:
            return _wifi_event(ts, hostname, raw,
                               action="roam",
                               client_mac=m.group("mac"),
                               iface=m.group("to_if"),
                               ev_type=["info"], outcome="success",
                               msg=f"Wireless STA {m.group('mac')} roamed {m.group('from_if')} -> {m.group('to_if')}",
                               labels={"from_interface": m.group("from_if"), "to_interface": m.group("to_if")})

        return None


def _wifi_event(
    ts: datetime,
    hostname: Optional[str],
    raw: str,
    action: str,
    client_mac: Optional[str] = None,
    iface: Optional[str] = None,
    bssid: Optional[str] = None,
    ssid: Optional[str] = None,
    signal: Optional[str] = None,
    reason_code: Optional[str] = None,
    ev_type: Optional[list] = None,
    outcome: str = "success",
    msg: str = "",
    severity: int = 2,
    labels: Optional[dict] = None,
) -> ParsedEvent:
    lbl: dict = {"wifi_action": action}
    if iface:
        lbl["interface"] = iface
    if bssid:
        lbl["bssid"] = bssid
    if ssid:
        lbl["ssid"] = ssid[:64]
    if signal:
        lbl["signal_dbm"] = signal
    if reason_code:
        lbl["reason_code"] = reason_code
    if labels:
        lbl.update(labels)

    return ParsedEvent(
        timestamp=ts,
        dataset="unifi.wireless",
        event_kind="event",
        event_category=["session"],
        event_type=ev_type or ["info"],
        event_severity=severity,
        event_outcome=outcome,
        source_mac=client_mac,
        hostname=hostname,
        observer_type="firewall",
        tags=["wireless", "wifi"],
        labels=lbl,
        message=msg,
        raw_message=raw,
    )
