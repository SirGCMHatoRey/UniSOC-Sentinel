"""
Async SMTP email sender with exponential-backoff retry logic.

Sends HTML alert emails via aiosmtplib with optional STARTTLS and
authenticated login.  On transient connection failures the send is
retried up to MAX_ATTEMPTS times with delays of 1 s, 2 s, 4 s.

If all retries are exhausted an exception is raised so the caller can
update the error metric and continue processing the next alert.
"""

from __future__ import annotations

import asyncio
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import aiosmtplib
import structlog

from .config import Settings
from .metrics import Metrics

log: structlog.stdlib.BoundLogger = structlog.get_logger(__name__)

MAX_ATTEMPTS = 3
BASE_BACKOFF_SECONDS = 1.0  # 1 s, 2 s, 4 s


class EmailSender:
    """
    Sends HTML emails via async SMTP.

    A new SMTP connection is opened per message (stateless model suitable
    for low-to-medium alert volumes).  TLS/STARTTLS negotiation and
    authentication are performed on every connection.

    Args:
        config:  Service settings (SMTP host/port/credentials).
        metrics: Prometheus metrics instance.
    """

    def __init__(self, config: Settings, metrics: Metrics) -> None:
        self._config = config
        self._metrics = metrics

    async def send(
        self,
        subject: str,
        html_body: str,
        recipients: list[str],
    ) -> None:
        """
        Send an HTML email to *recipients* with exponential-backoff retries.

        Args:
            subject:    Email subject line.
            html_body:  Fully rendered HTML email body.
            recipients: List of recipient email addresses.

        Raises:
            RuntimeError: After all retry attempts are exhausted.
        """
        if not recipients:
            log.warning("No recipients configured; skipping email send")
            return

        msg = self._build_message(subject, html_body, recipients)
        last_exc: Exception | None = None

        for attempt in range(1, MAX_ATTEMPTS + 1):
            try:
                await self._do_send(msg)
                log.info(
                    "Email sent",
                    subject=subject,
                    recipients=recipients,
                    attempt=attempt,
                )
                return  # success — exit retry loop

            except (aiosmtplib.SMTPException, OSError, ConnectionError) as exc:
                last_exc = exc
                backoff = BASE_BACKOFF_SECONDS * (2 ** (attempt - 1))  # 1 s, 2 s, 4 s
                log.warning(
                    "Email send failed",
                    attempt=attempt,
                    max_attempts=MAX_ATTEMPTS,
                    error=str(exc),
                    retry_in_seconds=backoff if attempt < MAX_ATTEMPTS else None,
                )
                if attempt < MAX_ATTEMPTS:
                    await asyncio.sleep(backoff)

        # All attempts exhausted
        self._metrics.email_errors_total.inc()
        raise RuntimeError(
            f"Email send failed after {MAX_ATTEMPTS} attempts: {last_exc}"
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _build_message(
        self,
        subject: str,
        html_body: str,
        recipients: list[str],
    ) -> MIMEMultipart:
        """
        Construct a MIME multipart/alternative email message.

        Args:
            subject:    Email subject string.
            html_body:  HTML content for the message body.
            recipients: List of To: addresses.

        Returns:
            A fully assembled MIMEMultipart message object.
        """
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = self._config.smtp_from
        msg["To"] = ", ".join(recipients)
        msg["X-Mailer"] = "UniSOC-Sentinel-Notifier/1.0"

        # Plain-text fallback for email clients that don't render HTML
        plain_text = (
            f"UniSOC Sentinel Security Alert\n\n"
            f"Subject: {subject}\n\n"
            "This alert requires an HTML-capable email client to view properly.\n"
        )
        msg.attach(MIMEText(plain_text, "plain", "utf-8"))
        msg.attach(MIMEText(html_body, "html", "utf-8"))

        return msg

    async def _do_send(self, msg: MIMEMultipart) -> None:
        """
        Open an SMTP connection, negotiate TLS, authenticate, and send *msg*.

        A fresh connection is used for each send call to avoid connection
        timeout issues on low-traffic deployments.

        Args:
            msg: The pre-built MIME message to deliver.
        """
        smtp = aiosmtplib.SMTP(
            hostname=self._config.smtp_host,
            port=self._config.smtp_port,
            timeout=30,
        )
        async with smtp:
            if self._config.smtp_starttls:
                await smtp.starttls()

            smtp_password = self._config.smtp_password
            if self._config.smtp_user and smtp_password:
                await smtp.login(self._config.smtp_user, smtp_password)

            recipients = [addr.strip() for addr in msg["To"].split(",")]
            await smtp.send_message(msg, recipients=recipients)
