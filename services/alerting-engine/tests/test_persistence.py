"""
Tests for the alert persistence layer (services/alerting-engine/src/persistence.py).

Seam under test: AlertPersistence no longer owns a competing ORM model or
schema for the `alerts` table (see issue #6) — it writes through a plain
Core `Table` whose columns mirror siem-core's Alert model exactly, and
`init_schema()` performs no DDL. A real Postgres connection isn't available
in this test environment (and JSONB is Postgres-specific, so there's no
drop-in local substitute), so the AsyncSession boundary is mocked to
inspect what `save()`/`init_schema()` actually try to do.
"""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy.dialects import postgresql

from src.persistence import AlertPersistence, alerts_table


@pytest.fixture
def sample_alert() -> dict:
    return {
        "id": "11111111-1111-1111-1111-111111111111",
        "rule_id": "brute_force",
        "rule_name": "Brute Force Detection",
        "severity": "high",
        "title": "Brute force attempt detected",
        "description": "10 failed logins from 203.0.113.5 in 5 minutes",
        "created_at": "2026-08-01T00:00:00Z",
        "event_count": 10,
        "metadata": {"source_ip": "203.0.113.5"},
    }


def _load_siem_core_alert_columns() -> dict[str, str]:
    """
    Return {column_name: postgres_type_str} for siem-core's real Alert
    model, read via a subprocess in siem-core's own directory.

    A subprocess (not an in-process import) is required because both
    services' packages are top-level-named `src` — importing siem-core's
    `src.models.alert` into this process would collide with (or be
    shadowed by) alerting-engine's already-imported `src` package.
    """
    siem_core_dir = Path(__file__).resolve().parents[2] / "siem-core"
    script = (
        "from sqlalchemy.dialects import postgresql\n"
        "from src.models.alert import Alert\n"
        "import json\n"
        "print(json.dumps({\n"
        "    c.name: c.type.compile(dialect=postgresql.dialect())\n"
        "    for c in Alert.__table__.columns\n"
        "}))\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=siem_core_dir,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, f"Failed to load siem-core's Alert model:\n{result.stderr}"
    return json.loads(result.stdout)


def test_alerts_table_columns_match_siem_core_model_types():
    # This is the drift check: every column alerting-engine's write-only
    # Table declares must exist in siem-core's actual schema-owning model
    # with the same Postgres type — not just self-consistency within this
    # file. Catches a future column rename/retype in siem-core's model that
    # this file wasn't updated to match, before it becomes a runtime insert
    # failure.
    siem_core_columns = _load_siem_core_alert_columns()

    for column in alerts_table.columns:
        assert column.name in siem_core_columns, (
            f"alerting-engine writes column {column.name!r} which does not "
            f"exist in siem-core's Alert model"
        )
        our_type = column.type.compile(dialect=postgresql.dialect())
        assert our_type == siem_core_columns[column.name], (
            f"Column {column.name!r} type mismatch: alerting-engine declares "
            f"{our_type!r}, siem-core's model has {siem_core_columns[column.name]!r}"
        )

    # siem-core is allowed extra columns alerting-engine never writes
    # (acknowledged, acknowledged_by, acknowledged_at) — that's expected,
    # not drift.
    extra_in_siem_core = set(siem_core_columns) - {c.name for c in alerts_table.columns}
    assert extra_in_siem_core == {"acknowledged", "acknowledged_by", "acknowledged_at"}


def test_alerts_table_columns_mirror_siem_core_schema():
    # Column set (and the "metadata" DB column name, not "metadata_") must
    # match services/siem-core/src/models/alert.py exactly — that's the
    # whole point of the fix: one schema, described identically wherever
    # it's written to.
    assert set(alerts_table.columns.keys()) == {
        "id",
        "rule_id",
        "rule_name",
        "severity",
        "title",
        "description",
        "created_at",
        "event_count",
        "metadata",
    }


def test_alert_persistence_has_no_create_all_capability():
    # There must be no declarative Base/metadata.create_all path left in
    # this module — AlertPersistence should not be able to create or alter
    # the alerts table at all.
    import src.persistence as persistence_module

    assert not hasattr(persistence_module, "Base")
    assert not hasattr(persistence_module, "Alert")


@pytest.mark.asyncio
async def test_init_schema_does_not_issue_ddl():
    persistence = AlertPersistence.__new__(AlertPersistence)
    mock_conn = AsyncMock()
    mock_engine = MagicMock()
    mock_engine.connect.return_value.__aenter__.return_value = mock_conn
    mock_engine.connect.return_value.__aexit__.return_value = None
    persistence._engine = mock_engine

    await persistence.init_schema()

    mock_conn.execute.assert_awaited_once()
    executed_sql = str(mock_conn.execute.await_args.args[0])
    assert "SELECT 1" in executed_sql
    assert "CREATE TABLE" not in executed_sql.upper()


@pytest.mark.asyncio
async def test_save_inserts_all_fields_via_core_table(sample_alert):
    persistence = AlertPersistence.__new__(AlertPersistence)
    mock_session = AsyncMock()
    mock_session_cm = MagicMock()
    mock_session_cm.__aenter__.return_value = mock_session
    mock_session_cm.__aexit__.return_value = None
    persistence._session_factory = MagicMock(return_value=mock_session_cm)

    await persistence.save(sample_alert)

    mock_session.execute.assert_awaited_once()
    statement = mock_session.execute.await_args.args[0]
    compiled_params = statement.compile().params

    assert compiled_params["id"] == sample_alert["id"]
    assert compiled_params["rule_id"] == sample_alert["rule_id"]
    assert compiled_params["severity"] == sample_alert["severity"]
    assert compiled_params["metadata"] == sample_alert["metadata"]
    assert compiled_params["created_at"] == datetime(
        2026, 8, 1, 0, 0, 0, tzinfo=timezone.utc
    )
    mock_session.commit.assert_awaited_once()
