"""
Jinja2 email template renderer for the email-notifier service.

Maps alert rule IDs to purpose-built HTML email templates and renders
them with alert data.  Falls back to the generic alert template for any
rule ID not explicitly mapped.
"""

from __future__ import annotations

import structlog
from jinja2 import Environment, FileSystemLoader, select_autoescape

log: structlog.stdlib.BoundLogger = structlog.get_logger(__name__)

# Maps rule_id -> template filename
TEMPLATE_MAP: dict[str, str] = {
    "multiple_failed_logins": "brute_force.html",
    "threat_management_trigger": "threat_management.html",
    "rogue_ap_detection": "rogue_ap.html",
    "vpn_anomaly": "vpn_anomaly.html",
    "bandwidth_spike": "bandwidth.html",
    "device_offline": "device_offline.html",
    "critical_firewall_event": "firewall.html",
}

FALLBACK_TEMPLATE = "alert_generic.html"


class EmailRenderer:
    """
    Renders HTML email bodies from Jinja2 templates.

    Templates live in *template_dir* and extend ``base.html`` for
    consistent styling.  The ``alert`` variable is always available in
    the template context; additional keyword arguments from
    ``alert.metadata`` are also merged so templates can reference e.g.
    ``{{ source_ip }}`` directly.

    Args:
        template_dir: Filesystem path to the directory containing the
                      Jinja2 template files.
    """

    def __init__(self, template_dir: str) -> None:
        self._env = Environment(
            loader=FileSystemLoader(template_dir),
            autoescape=select_autoescape(["html"]),
            trim_blocks=True,
            lstrip_blocks=True,
        )

    def render(self, rule_id: str, alert: dict) -> tuple[str, str]:
        """
        Render the email subject line and HTML body for an alert.

        Selects the best-matching template based on *rule_id*, then
        renders it with the alert dict as context.

        Args:
            rule_id: The alert's rule identifier (e.g. "multiple_failed_logins").
            alert:   The full alert dict conforming to the shared interface
                     contract.

        Returns:
            A ``(subject, html_body)`` tuple.

        Raises:
            jinja2.TemplateNotFound: If the resolved template file is missing
                                     (the generic fallback must always exist).
        """
        template_name = TEMPLATE_MAP.get(rule_id, FALLBACK_TEMPLATE)

        log.debug(
            "Rendering email template",
            rule_id=rule_id,
            template=template_name,
        )

        try:
            template = self._env.get_template(template_name)
        except Exception:
            log.warning(
                "Template not found, falling back to generic",
                template=template_name,
                rule_id=rule_id,
            )
            template = self._env.get_template(FALLBACK_TEMPLATE)

        severity = alert.get("severity", "info").upper()
        title = alert.get("title", "Security Alert")
        subject = f"[{severity}] UniSOC Alert: {title}"

        # Merge metadata into context so templates can use {{ source_ip }} etc.
        metadata = alert.get("metadata") or {}
        context = {"alert": alert, **metadata}

        html = template.render(**context)
        return subject, html
