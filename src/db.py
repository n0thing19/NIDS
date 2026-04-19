from __future__ import annotations

import json
from typing import Any, Dict, Iterable, Optional

import psycopg2
from psycopg2.extensions import connection as PgConnection
from psycopg2.extras import Json


CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS raw_network_events (
    id BIGSERIAL PRIMARY KEY,
    source TEXT NOT NULL,
    captured_at TIMESTAMPTZ NOT NULL,
    kafka_topic TEXT,
    kafka_partition INTEGER,
    kafka_offset BIGINT,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"""


INSERT_SQL = """
INSERT INTO raw_network_events (
    source,
    captured_at,
    kafka_topic,
    kafka_partition,
    kafka_offset,
    payload
) VALUES (%s, %s, %s, %s, %s, %s);
"""


def create_connection(database_url: str) -> PgConnection:
    return psycopg2.connect(database_url)


def _sanitize_string_for_db(value: str) -> str:
    # Remove BOM marker and drop characters unsupported by WIN1252 servers.
    cleaned = value.replace("\ufeff", "")
    return cleaned.encode("cp1252", errors="ignore").decode("cp1252")


def _sanitize_payload_for_db(value: Any) -> Any:
    if isinstance(value, dict):
        return {_sanitize_string_for_db(str(k)): _sanitize_payload_for_db(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_sanitize_payload_for_db(v) for v in value]
    if isinstance(value, str):
        return _sanitize_string_for_db(value)
    return value


def init_db(conn: PgConnection) -> None:
    with conn, conn.cursor() as cur:
        cur.execute(CREATE_TABLE_SQL)


def save_event(
    conn: PgConnection,
    *,
    source: str,
    captured_at: str,
    payload: Dict[str, Any],
    kafka_topic: Optional[str] = None,
    kafka_partition: Optional[int] = None,
    kafka_offset: Optional[int] = None,
) -> None:
    payload = _sanitize_payload_for_db(payload)

    with conn, conn.cursor() as cur:
        cur.execute(
            INSERT_SQL,
            (
                source,
                captured_at,
                kafka_topic,
                kafka_partition,
                kafka_offset,
                Json(payload),
            ),
        )


def dump_event_json(event: Dict[str, Any]) -> str:
    return json.dumps(event, separators=(",", ":"), ensure_ascii=True)
