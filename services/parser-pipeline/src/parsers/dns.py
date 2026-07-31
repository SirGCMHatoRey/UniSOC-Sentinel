"""Parser for DNS log entries (dnsmasq)."""
from __future__ import annotations

import re
from datetime import datetime
from typing import Optional

from .base import BaseParser, ParsedEvent

# ---------------------------------------------------------------------------
# dnsmasq DNS patterns
# ---------------------------------------------------------------------------

# query[A] example.com from 192.168.1.1
_DNS_QUERY = re.compile(
    r"query\[(?P<qtype>[A-Z0-9]+)\]\s+(?P<domain>\S+)\s+from\s+(?P<ip>[\d.]+)",
    re.IGNORECASE,
)

# forwarded example.com to 8.8.8.8
_DNS_FORWARD = re.compile(
    r"forwarded\s+(?P<domain>\S+)\s+to\s+(?P<upstream>[\d.]+)",
    re.IGNORECASE,
)

# cached example.com is 1.2.3.4
_DNS_CACHED = re.compile(
    r"cached\s+(?P<domain>\S+)\s+is\s+(?P<result>\S+)",
    re.IGNORECASE,
)

# reply example.com is 1.2.3.4  (or is NXDOMAIN, is NODATA-IPv6, is <CNAME>)
_DNS_REPLY = re.compile(
    r"reply\s+(?P<domain>\S+)\s+is\s+(?P<result>\S+)",
    re.IGNORECASE,
)

# NXDOMAIN: "config example.com is NXDOMAIN" or "reply ... is NXDOMAIN"
_DNS_NXDOMAIN = re.compile(
    r"(?:reply|config)\s+(?P<domain>\S+)\s+is\s+NXDOMAIN",
    re.IGNORECASE,
)

# config example.com is 1.2.3.4  (local override)
_DNS_CONFIG = re.compile(
    r"config\s+(?P<domain>\S+)\s+is\s+(?P<result>\S+)",
    re.IGNORECASE,
)

# dnsmasq started (startup event)
_DNS_START = re.compile(r"dnsmasq.*started", re.IGNORECASE)

# DNSSEC validation
_DNS_DNSSEC = re.compile(
    r"(?:DNSSEC\s+)?(?:validated|verify(?:ing)?|bogus)\s+(?P<domain>\S+)",
    re.IGNORECASE,
)

# blocked by blocklist
_DNS_BLOCKED = re.compile(
    r"(?:blocked|blacklisted)\s+(?P<domain>\S+)\s+(?:from\s+(?P<ip>[\d.]+))?",
    re.IGNORECASE,
)

_DNS_PROGRAMS = frozenset({"dnsmasq", "dnsmasq-dhcp", "named", "unbound", "dns"})
_DNS_KEYWORDS = re.compile(
    r"query\[(?:A|AAAA|PTR|MX|TXT|SRV|CNAME|NS|SOA|ANY)\]"
    r"|forwarded .+ to [\d.]"
    r"|cached .+ is "
    r"|reply .+ is "
    r"|NXDOMAIN"
    r"|dnsmasq.*query",
    re.IGNORECASE,
)


class DNSParser(BaseParser):
    """Parse DNS log entries from dnsmasq and other resolvers."""

    def can_parse(self, raw: str, program: Optional[str], hostname: Optional[str]) -> bool:
        prog_match = program and program.lower().split("[")[0] in _DNS_PROGRAMS
        kw_match = bool(_DNS_KEYWORDS.search(raw))
        return bool(kw_match)

    def parse(self, raw: str, source_ip: str, received_at: datetime) -> Optional[ParsedEvent]:
        try:
            return self._parse(raw, source_ip, received_at)
        except Exception:
            return None

    def _parse(self, raw: str, source_ip: str, received_at: datetime) -> Optional[ParsedEvent]:
        ts, hostname, program, msg = self._extract_syslog_header(raw)
        ts = ts or received_at

        # Blocked by blocklist (check before generic query)
        m = _DNS_BLOCKED.search(raw)
        if m:
            domain = m.group("domain")
            client_ip = m.group("ip") if m.lastindex and m.lastindex >= 2 else None
            return _dns_event(ts, hostname, raw,
                              query_type="blocked", domain=domain, client_ip=client_ip,
                              result="blocked", outcome="failure",
                              msg=f"DNS blocked: {domain} from {client_ip or '?'}",
                              severity=6)

        # NXDOMAIN
        m = _DNS_NXDOMAIN.search(raw)
        if m:
            domain = m.group("domain")
            # Also try to get client IP from a query line in the same log entry
            mq = _DNS_QUERY.search(raw)
            client_ip = mq.group("ip") if mq else None
            return _dns_event(ts, hostname, raw,
                              query_type="A", domain=domain, client_ip=client_ip,
                              result="NXDOMAIN", outcome="unknown",
                              msg=f"DNS NXDOMAIN: {domain}")

        # DNS query
        m = _DNS_QUERY.search(raw)
        if m:
            domain = m.group("domain")
            qtype = m.group("qtype").upper()
            client_ip = m.group("ip")

            # Determine result from subsequent lines (best effort from same raw)
            result = "queried"
            m_rep = _DNS_REPLY.search(raw)
            if m_rep:
                result = m_rep.group("result")
            elif _DNS_NXDOMAIN.search(raw):
                result = "NXDOMAIN"

            return _dns_event(ts, hostname, raw,
                              query_type=qtype, domain=domain, client_ip=client_ip,
                              result=result,
                              msg=f"DNS query [{qtype}] {domain} from {client_ip}")

        # Forwarded
        m = _DNS_FORWARD.search(raw)
        if m:
            return _dns_event(ts, hostname, raw,
                              query_type="forward", domain=m.group("domain"),
                              upstream=m.group("upstream"),
                              msg=f"DNS forwarded {m.group('domain')} to {m.group('upstream')}")

        # Cached reply
        m = _DNS_CACHED.search(raw)
        if m:
            return _dns_event(ts, hostname, raw,
                              query_type="cached", domain=m.group("domain"),
                              result=m.group("result"),
                              msg=f"DNS cached {m.group('domain')} -> {m.group('result')}")

        # Reply
        m = _DNS_REPLY.search(raw)
        if m:
            return _dns_event(ts, hostname, raw,
                              query_type="reply", domain=m.group("domain"),
                              result=m.group("result"),
                              msg=f"DNS reply {m.group('domain')} -> {m.group('result')}")

        return None


def _dns_event(
    ts: datetime,
    hostname: Optional[str],
    raw: str,
    query_type: str,
    domain: str,
    client_ip: Optional[str] = None,
    upstream: Optional[str] = None,
    result: Optional[str] = None,
    outcome: str = "success",
    msg: str = "",
    severity: int = 1,
) -> ParsedEvent:
    labels: dict = {
        "query_type": query_type,
        "domain": domain[:253],
    }
    if upstream:
        labels["upstream"] = upstream
    if result:
        labels["result"] = result[:128]

    return ParsedEvent(
        timestamp=ts,
        dataset="unifi.dns",
        event_kind="event",
        event_category=["network"],
        event_type=["info"],
        event_severity=severity,
        event_outcome=outcome,
        source_ip=client_ip,
        hostname=hostname,
        observer_type="firewall",
        tags=["dns"],
        labels=labels,
        message=msg,
        raw_message=raw,
    )
