from __future__ import annotations

import argparse
import json

from dotenv import load_dotenv
from kafka import KafkaConsumer

from src.config import load_config
from src.db import create_connection, init_db, save_event


def build_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Consume Kafka raw events and store them in PostgreSQL")
    parser.add_argument("--max-messages", type=int, default=0, help="Stop after N messages (0 means unlimited)")
    return parser.parse_args()


def main() -> None:
    load_dotenv()
    args = build_args()
    cfg = load_config()

    if not cfg.database_url:
        raise RuntimeError("DATABASE_URL or PGHOST/PGPORT/PGDATABASE/PGUSER/PGPASSWORD must be set")

    conn = create_connection(cfg.database_url)
    init_db(conn)

    consumer = KafkaConsumer(
        cfg.kafka_raw_topic,
        bootstrap_servers=cfg.kafka_bootstrap_servers,
        group_id=cfg.kafka_group_id,
        client_id=f"{cfg.kafka_client_id}-postgres-consumer",
        auto_offset_reset="earliest",
        enable_auto_commit=True,
        value_deserializer=lambda v: json.loads(v.decode("utf-8")),
    )

    count = 0
    try:
        for msg in consumer:
            event = msg.value
            captured_at = event.get("captured_at")
            source = event.get("source", "unknown")

            if not captured_at:
                continue

            save_event(
                conn,
                source=source,
                captured_at=captured_at,
                payload=event,
                kafka_topic=msg.topic,
                kafka_partition=msg.partition,
                kafka_offset=msg.offset,
            )

            count += 1
            if args.max_messages and count >= args.max_messages:
                break
    finally:
        consumer.close()
        conn.close()


if __name__ == "__main__":
    main()
