from __future__ import annotations

import argparse
import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict

from dotenv import load_dotenv
from kafka import KafkaProducer

from src.config import load_config


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def build_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Publish CSV rows as raw events to Kafka")
    parser.add_argument("--csv", required=True, help="Path to CSV file for testing")
    parser.add_argument("--source", default="csv_test", help="Source tag to store in events")
    parser.add_argument("--limit", type=int, default=0, help="Max rows to publish (0 means all rows)")
    return parser.parse_args()


def row_to_event(row: Dict[str, str], source: str, row_number: int, csv_name: str) -> Dict[str, object]:
    return {
        "source": source,
        "captured_at": _utc_now_iso(),
        "csv_file": csv_name,
        "csv_row_number": row_number,
        "row": row,
    }


def main() -> None:
    load_dotenv()
    args = build_args()
    cfg = load_config()

    csv_path = Path(args.csv)
    if not csv_path.exists():
        raise FileNotFoundError(f"CSV not found: {csv_path}")

    producer = KafkaProducer(
        bootstrap_servers=cfg.kafka_bootstrap_servers,
        client_id=f"{cfg.kafka_client_id}-csv-producer",
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
    )

    with csv_path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        for idx, row in enumerate(reader, start=1):
            if args.limit and idx > args.limit:
                break
            event = row_to_event(row, source=args.source, row_number=idx, csv_name=csv_path.name)
            producer.send(cfg.kafka_raw_topic, event)

    producer.flush()
    producer.close()


if __name__ == "__main__":
    main()
