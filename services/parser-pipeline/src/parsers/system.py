"""Parser for system event log entries (kernel OOM, CPU, disk, services)."""
from __future__ import annotations

import re
from datetime import datetime
from typing import Optional

from .base import BaseParser, ParsedEvent

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

# Kernel OOM: Out of memory: Kill process <pid> (<name>) score <N> or sacrifice child
_OOM = re.compile(
    r"Out of memory:\s+Kill process (?P<pid>\d+) \((?P<proc>[^)]+)\) score (?P<score>\d+)",
    re.IGNORECASE,
)

# Kernel OOM: oom-kill:constraint=...,task=<name>,pid=<N>,...
_OOM_NEW = re.compile(
    r"oom-kill:.*?task=(?P<proc>[^,]+),pid=(?P<pid>\d+)",
    re.IGNORECASE,
)

# CPU throttling: CPU<N>: Core temperature above threshold
_CPU_THROTTLE = re.compile(
    r"CPU(?P<cpu>\d+):\s+(?:Core temperature|Package temperature)\s+above threshold",
    re.IGNORECASE,
)

# CPU throttle: thermal: CPU throttled
_CPU_THROTTLE2 = re.compile(
    r"(?:thermal|cpu).*?throttl(?:ed|ing)",
    re.IGNORECASE,
)

# Disk full: No space left on device / write failed
_DISK_FULL = re.compile(
    r"(?:No space left on device|write error.*ENOSPC|disk.*full)",
    re.IGNORECASE,
)

# Disk error: I/O error / SCSI error
_DISK_IO_ERROR = re.compile(
    r"(?:I/O error|SCSI error|Buffer I/O error).*?(?:device\s+(?P<dev>\S+))?",
    re.IGNORECASE,
)

# Service start: systemd: Started <service>
_SERVICE_START = re.compile(
    r"systemd.*?Started\s+(?P<service>.+?)\.?$",
    re.IGNORECASE,
)

# Service stop/failed: systemd: <service>.service: Failed / Stopped
_SERVICE_STOP = re.compile(
    r"systemd.*?(?:Stopped|Failed\s+to\s+start|Deactivated)\s+(?P<service>.+?)\.?$",
    re.IGNORECASE,
)

# Service crash: segfault at <addr>
_SEGFAULT = re.compile(
    r"(?P<prog>\S+)\[(?P<pid>\d+)\]:\s+segfault at (?P<addr>\S+)",
    re.IGNORECASE,
)

# Hardware error: MCE, parity, ECC
_HW_ERROR = re.compile(
    r"(?:MCE\s+\d+|Hardware Error|ECC\s+error|parity\s+error|NMI\s+watchdog)",
    re.IGNORECASE,
)

# Network interface: eth0: Link is Up/Down
_LINK_STATE = re.compile(
    r"(?P<iface>\w+(?:\.\d+)?): Link is (?P<state>Up|Down)",
    re.IGNORECASE,
)

# Kernel panic
_KERNEL_PANIC = re.compile(r"Kernel panic", re.IGNORECASE)

# watchdog reset
_WATCHDOG = re.compile(r"watchdog.*?(?:reset|timeout|bite)", re.IGNORECASE)

_SYSTEM_PROGRAMS = frozenset({
    "kernel", "systemd", "systemd-journald", "init", "watchdog",
    "mcelog", "rsyslogd", "syslogd",
})
_SYSTEM_KEYWORDS = re.compile(
    r"Out of memory:|oom-kill:|Core temperature above|No space left"
    r"|I/O error|Buffer I/O error|SCSI error"
    r"|systemd.*Started|systemd.*Failed|systemd.*Stopped"
    r"|segfault at|Kernel panic|MCE\s+\d+|watchdog.*(?:reset|timeout)"
    r"|Link is (?:Up|Down)",
    re.IGNORECASE,
)


class SystemParser(BaseParser):
    """Parse kernel / system events: OOM, CPU, disk, services, hardware."""

    def can_parse(self, raw: str, program: Optional[str], hostname: Optional[str]) -> bool:
        kw_match = bool(_SYSTEM_KEYWORDS.search(raw))
        # Be conservative — system events share program names with other parsers
        return kw_match

    def parse(self, raw: str, source_ip: str, received_at: datetime) -> Optional[ParsedEvent]:
        try:
            return self._parse(raw, source_ip, received_at)
        except Exception:
            return None

    def _parse(self, raw: str, source_ip: str, received_at: datetime) -> Optional[ParsedEvent]:
        ts, hostname, program, msg = self._extract_syslog_header(raw)
        ts = ts or received_at

        # OOM kill
        m = _OOM.search(raw)
        if m:
            return _sys_event(ts, hostname, raw, "oom_kill",
                              labels={"killed_process": m.group("proc"),
                                      "killed_pid": m.group("pid"),
                                      "oom_score": m.group("score")},
                              msg=f"OOM: killed process {m.group('proc')} (pid {m.group('pid')})",
                              severity=9)

        m = _OOM_NEW.search(raw)
        if m:
            return _sys_event(ts, hostname, raw, "oom_kill",
                              labels={"killed_process": m.group("proc"), "killed_pid": m.group("pid")},
                              msg=f"OOM kill: {m.group('proc')} (pid {m.group('pid')})",
                              severity=9)

        # Kernel panic
        if _KERNEL_PANIC.search(raw):
            return _sys_event(ts, hostname, raw, "kernel_panic",
                              msg="Kernel panic detected", severity=10)

        # Hardware error
        m = _HW_ERROR.search(raw)
        if m:
            return _sys_event(ts, hostname, raw, "hardware_error",
                              msg=f"Hardware error: {m.group(0)[:128]}", severity=9)

        # CPU throttle
        m = _CPU_THROTTLE.search(raw)
        if m:
            return _sys_event(ts, hostname, raw, "cpu_thermal",
                              labels={"cpu": m.group("cpu")},
                              msg=f"CPU{m.group('cpu')} temperature above threshold", severity=7)

        m = _CPU_THROTTLE2.search(raw)
        if m:
            return _sys_event(ts, hostname, raw, "cpu_throttle",
                              msg="CPU throttled due to thermal event", severity=6)

        # Disk full
        if _DISK_FULL.search(raw):
            return _sys_event(ts, hostname, raw, "disk_full",
                              msg="Disk full: no space left on device", severity=8)

        # Disk I/O error
        m = _DISK_IO_ERROR.search(raw)
        if m:
            dev = m.group("dev") if m.lastindex and m.lastindex >= 1 else "unknown"
            return _sys_event(ts, hostname, raw, "disk_io_error",
                              labels={"device": dev or "unknown"},
                              msg=f"Disk I/O error on {dev}", severity=8)

        # Segfault
        m = _SEGFAULT.search(raw)
        if m:
            return _sys_event(ts, hostname, raw, "segfault",
                              labels={"process": m.group("prog"), "pid": m.group("pid"),
                                      "address": m.group("addr")},
                              msg=f"Segfault in {m.group('prog')} at {m.group('addr')}", severity=6)

        # Service started
        m = _SERVICE_START.search(raw)
        if m:
            return _sys_event(ts, hostname, raw, "service_start",
                              labels={"service": m.group("service").strip()},
                              msg=f"Service started: {m.group('service').strip()}", severity=2)

        # Service stopped/failed
        m = _SERVICE_STOP.search(raw)
        if m:
            failed = "fail" in raw.lower()
            return _sys_event(ts, hostname, raw,
                              "service_failed" if failed else "service_stop",
                              labels={"service": m.group("service").strip()},
                              msg=f"Service {'failed' if failed else 'stopped'}: {m.group('service').strip()}",
                              severity=7 if failed else 3)

        # Link state
        m = _LINK_STATE.search(raw)
        if m:
            state = m.group("state").lower()
            return _sys_event(ts, hostname, raw, f"link_{state}",
                              labels={"interface": m.group("iface")},
                              msg=f"Interface {m.group('iface')} link {state}", severity=4)

        # Watchdog
        if _WATCHDOG.search(raw):
            return _sys_event(ts, hostname, raw, "watchdog_reset",
                              msg="Watchdog reset/timeout", severity=8)

        return None


def _sys_event(
    ts: datetime,
    hostname: Optional[str],
    raw: str,
    event_type: str,
    labels: Optional[dict] = None,
    msg: str = "",
    severity: int = 5,
) -> ParsedEvent:
    lbl = {"system_event_type": event_type}
    if labels:
        lbl.update(labels)
    return ParsedEvent(
        timestamp=ts,
        dataset="unifi.system",
        event_kind="event",
        event_category=["process"],
        event_type=["info"],
        event_severity=severity,
        event_outcome="unknown",
        hostname=hostname,
        observer_type="host",
        tags=["system"],
        labels=lbl,
        message=msg,
        raw_message=raw,
    )
