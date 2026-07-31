"""Parser for authentication log entries (SSH, PAM, login)."""
from __future__ import annotations

import re
from datetime import datetime
from typing import Optional

from .base import BaseParser, ParsedEvent

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

# sshd: Failed password for [invalid user] <user> from <ip> port <port> ssh2
_SSH_FAILED_PASSWORD = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)",
)

# sshd: Accepted password for <user> from <ip> port <port> ssh2
_SSH_ACCEPTED_PASSWORD = re.compile(
    r"Accepted password for (?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)",
)

# sshd: Accepted publickey for <user> from <ip> port <port> ssh2: RSA ...
_SSH_ACCEPTED_PUBKEY = re.compile(
    r"Accepted publickey for (?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)",
)

# sshd: Failed publickey for <user> from <ip> port <port>
_SSH_FAILED_PUBKEY = re.compile(
    r"Failed publickey for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)",
)

# sshd: Invalid user <user> from <ip> port <port>
_SSH_INVALID_USER = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>[\d.]+)(?:\s+port (?P<port>\d+))?",
)

# sshd: Connection closed by [invalid user] <user> <ip> port <port> [preauth]
_SSH_CONN_CLOSED = re.compile(
    r"Connection closed by (?:invalid user )?(?P<user>\S+)? ?(?P<ip>[\d.]+) port (?P<port>\d+)",
)

# sshd: Disconnected from [invalid user] <user> <ip> port <port> [preauth]
_SSH_DISCONNECTED = re.compile(
    r"Disconnected from (?:invalid user )?(?P<user>\S+)? ?(?P<ip>[\d.]+) port (?P<port>\d+)",
)

# pam_unix: authentication failure; user=<user> rhost=<ip>
_PAM_AUTH_FAILURE = re.compile(
    r"pam_unix\S*: authentication failure;.*?(?:user=(?P<user>\S+))?.*?(?:rhost=(?P<ip>[\d.]+))?",
)

# pam_unix: session opened/closed for user <user>
_PAM_SESSION = re.compile(
    r"pam_unix\S*: session (?P<action>opened|closed) for user (?P<user>\S+)",
)

# login: FAILED LOGIN <n> FROM <tty> FOR <user>
_LOGIN_FAILED = re.compile(
    r"FAILED LOGIN\s+\d+\s+FROM\s+(?P<tty>\S+)\s+FOR\s+(?P<user>\S+)",
)

# su: authentication failure for <user>; logname= uid=... ruser=...
_SU_FAILURE = re.compile(
    r"su:.*authentication failure.*?user=(?P<user>\S+)",
)

# sudo: <user> : ... COMMAND=...
_SUDO_RE = re.compile(
    r"sudo:\s+(?P<user>\S+)\s+:.*?(?:COMMAND=(?P<cmd>.+))?$",
)

_AUTH_PROGRAMS = frozenset({"sshd", "ssh", "login", "su", "sudo", "pam_unix", "auth"})
_AUTH_KEYWORDS = re.compile(
    r"Failed password|Accepted password|Accepted publickey|Failed publickey"
    r"|Invalid user|pam_unix.*authentication failure"
    r"|FAILED LOGIN|authentication failure"
    r"|session opened.*for user|session closed.*for user",
    re.IGNORECASE,
)


class AuthParser(BaseParser):
    """Parse SSH, PAM, and login authentication events."""

    def can_parse(self, raw: str, program: Optional[str], hostname: Optional[str]) -> bool:
        prog_match = program and program.lower().split("[")[0] in _AUTH_PROGRAMS
        kw_match = bool(_AUTH_KEYWORDS.search(raw))
        return bool(prog_match and kw_match) or bool(kw_match)

    def parse(self, raw: str, source_ip: str, received_at: datetime) -> Optional[ParsedEvent]:
        try:
            return self._parse(raw, source_ip, received_at)
        except Exception:
            return None

    def _parse(self, raw: str, source_ip: str, received_at: datetime) -> Optional[ParsedEvent]:
        ts, hostname, program, msg = self._extract_syslog_header(raw)
        ts = ts or received_at

        # SSH failed password
        m = _SSH_FAILED_PASSWORD.search(raw)
        if m:
            return _auth_event(
                ts=ts, hostname=hostname, raw=raw,
                username=m.group("user"), src_ip=m.group("ip"),
                src_port=self._safe_int(m.group("port")),
                success=False, method="password",
                msg=f"SSH failed password for {m.group('user')} from {m.group('ip')}",
            )

        # SSH accepted password
        m = _SSH_ACCEPTED_PASSWORD.search(raw)
        if m:
            return _auth_event(
                ts=ts, hostname=hostname, raw=raw,
                username=m.group("user"), src_ip=m.group("ip"),
                src_port=self._safe_int(m.group("port")),
                success=True, method="password",
                msg=f"SSH accepted password for {m.group('user')} from {m.group('ip')}",
            )

        # SSH accepted publickey
        m = _SSH_ACCEPTED_PUBKEY.search(raw)
        if m:
            return _auth_event(
                ts=ts, hostname=hostname, raw=raw,
                username=m.group("user"), src_ip=m.group("ip"),
                src_port=self._safe_int(m.group("port")),
                success=True, method="publickey",
                msg=f"SSH accepted publickey for {m.group('user')} from {m.group('ip')}",
            )

        # SSH failed publickey
        m = _SSH_FAILED_PUBKEY.search(raw)
        if m:
            return _auth_event(
                ts=ts, hostname=hostname, raw=raw,
                username=m.group("user"), src_ip=m.group("ip"),
                src_port=self._safe_int(m.group("port")),
                success=False, method="publickey",
                msg=f"SSH failed publickey for {m.group('user')} from {m.group('ip')}",
            )

        # SSH invalid user
        m = _SSH_INVALID_USER.search(raw)
        if m:
            port_str = m.group("port") if m.lastindex and m.lastindex >= 3 else None
            return _auth_event(
                ts=ts, hostname=hostname, raw=raw,
                username=m.group("user"), src_ip=m.group("ip"),
                src_port=self._safe_int(port_str),
                success=False, method="unknown",
                msg=f"SSH invalid user {m.group('user')} from {m.group('ip')}",
                severity=8,
            )

        # PAM auth failure
        m = _PAM_AUTH_FAILURE.search(raw)
        if m:
            return _auth_event(
                ts=ts, hostname=hostname, raw=raw,
                username=m.group("user"), src_ip=m.group("ip") or source_ip,
                src_port=None,
                success=False, method="pam",
                msg=f"PAM authentication failure for {m.group('user') or 'unknown'}",
            )

        # PAM session
        m = _PAM_SESSION.search(raw)
        if m:
            action = m.group("action")
            ev_type = ["start"] if action == "opened" else ["end"]
            return ParsedEvent(
                timestamp=ts,
                dataset="unifi.auth",
                event_kind="event",
                event_category=["authentication", "session"],
                event_type=ev_type,
                event_severity=2,
                event_outcome="success",
                hostname=hostname,
                username=m.group("user"),
                tags=["auth"],
                message=f"PAM session {action} for {m.group('user')}",
                raw_message=raw,
            )

        # Login failed
        m = _LOGIN_FAILED.search(raw)
        if m:
            return _auth_event(
                ts=ts, hostname=hostname, raw=raw,
                username=m.group("user"), src_ip=None,
                src_port=None,
                success=False, method="local",
                msg=f"Login failed for {m.group('user')}",
            )

        # Sudo
        m = _SUDO_RE.search(raw)
        if m:
            cmd = m.group("cmd") or ""
            return ParsedEvent(
                timestamp=ts,
                dataset="unifi.auth",
                event_kind="event",
                event_category=["authentication"],
                event_type=["info"],
                event_severity=3,
                event_outcome="success",
                hostname=hostname,
                username=m.group("user"),
                tags=["auth", "sudo"],
                labels={"command": cmd[:256]},
                message=f"sudo by {m.group('user')}: {cmd[:128]}",
                raw_message=raw,
            )

        return None


def _auth_event(
    ts: datetime,
    hostname: Optional[str],
    raw: str,
    username: Optional[str],
    src_ip: Optional[str],
    src_port: Optional[int],
    success: bool,
    method: str,
    msg: str,
    severity: Optional[int] = None,
) -> ParsedEvent:
    outcome = "success" if success else "failure"
    ev_type = ["start"] if success else ["denied"]
    sev = severity if severity is not None else (3 if success else 7)
    return ParsedEvent(
        timestamp=ts,
        dataset="unifi.auth",
        event_kind="event",
        event_category=["authentication"],
        event_type=ev_type,
        event_severity=sev,
        event_outcome=outcome,
        source_ip=src_ip,
        source_port=src_port or None,
        hostname=hostname,
        username=username,
        observer_type="firewall",
        tags=["auth"],
        labels={"auth_method": method},
        message=msg,
        raw_message=raw,
    )
