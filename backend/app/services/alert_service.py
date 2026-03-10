from __future__ import annotations

import os
import smtplib
from email.message import EmailMessage

from sqlalchemy.orm import Session

from app.models import Alert


class AlertService:
    def create_alert(self, db: Session, website: str, alert_type: str, message: str, metadata: dict) -> Alert:
        alert = Alert(website=website, alert_type=alert_type, message=message, metadata=metadata)
        db.add(alert)
        db.commit()
        db.refresh(alert)
        self._send_email_if_enabled(alert)
        return alert

    def _send_email_if_enabled(self, alert: Alert) -> None:
        host = os.getenv("SMTP_HOST")
        to_email = os.getenv("ALERT_EMAIL_TO")
        from_email = os.getenv("ALERT_EMAIL_FROM", "noreply@mumtathil.local")
        if not host or not to_email:
            return

        msg = EmailMessage()
        msg["Subject"] = f"[Mumtathil Alert] {alert.alert_type}"
        msg["From"] = from_email
        msg["To"] = to_email
        msg.set_content(f"Website: {alert.website}\n\n{alert.message}")

        with smtplib.SMTP(host, int(os.getenv("SMTP_PORT", "25"))) as smtp:
            smtp.send_message(msg)
