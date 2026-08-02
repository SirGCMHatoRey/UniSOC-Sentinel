"""
Regression test for the Alert ORM model (services/siem-core/src/models/alert.py).

`metadata` is reserved on SQLAlchemy DeclarativeBase subclasses (it's the
MetaData registry) — declaring a mapped column with that attribute name
raised `InvalidRequestError` at class-definition time, meaning the entire
siem-core service failed to import its models. This went unnoticed because
existing correlation-engine tests mock out `_persist_alert` entirely, so
the real `Alert(...)` constructor was never exercised — see issue #6.
"""

from __future__ import annotations

from datetime import datetime, timezone

from src.api.routes.alerts import AlertResponse
from src.models.alert import Alert


def test_alert_model_imports_and_constructs():
    alert = Alert(
        id="11111111-1111-1111-1111-111111111111",
        rule_id="vpn_anomaly",
        rule_name="VPN Login from New Geographic Location",
        severity="medium",
        title="VPN Geo-Anomaly: jdoe from Russia",
        description="User 'jdoe' connected via VPN from a new country: Russia (RU).",
        event_count=1,
        metadata_={"username": "jdoe", "new_country": "RU"},
        created_at=datetime(2026, 8, 1, tzinfo=timezone.utc),
    )
    assert alert.metadata_ == {"username": "jdoe", "new_country": "RU"}
    # The physical/JSON column name stays "metadata" even though the Python
    # attribute is metadata_ — this is what keeps the API contract stable.
    assert alerts_table_column_name(alert) == "metadata"


def test_alert_response_exposes_metadata_key_from_metadata_attribute():
    alert = Alert(
        id="11111111-1111-1111-1111-111111111111",
        rule_id="vpn_anomaly",
        rule_name="VPN Login from New Geographic Location",
        severity="medium",
        title="VPN Geo-Anomaly: jdoe from Russia",
        description="...",
        event_count=1,
        metadata_={"username": "jdoe"},
        acknowledged=False,
        acknowledged_by=None,
        acknowledged_at=None,
        created_at=datetime(2026, 8, 1, tzinfo=timezone.utc),
    )

    response = AlertResponse.model_validate(alert)

    assert response.metadata == {"username": "jdoe"}
    assert "metadata" in response.model_dump()
    assert "metadata_" not in response.model_dump()


def alerts_table_column_name(alert: Alert) -> str:
    return Alert.__table__.columns["metadata"].name
