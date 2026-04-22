from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

from dotenv import load_dotenv


@dataclass(frozen=True)
class AppConfig:
    kafka_bootstrap_servers: str
    kafka_raw_topic: str
    kafka_group_id: str
    kafka_client_id: str
    database_url: Optional[str]


def _build_database_url_from_parts() -> Optional[str]:
    host = os.getenv("PGHOST")
    port = os.getenv("PGPORT", "5432")
    db_name = os.getenv("PGDATABASE")
    user = os.getenv("PGUSER")
    password = os.getenv("PGPASSWORD")

    if not all([host, db_name, user, password]):
        return None

    return f"postgresql://{user}:{password}@{host}:{port}/{db_name}"


def load_config() -> AppConfig:
    load_dotenv(".env")

    database_url = os.getenv("DATABASE_URL") or _build_database_url_from_parts()

    return AppConfig(
        kafka_bootstrap_servers=os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092"),
        kafka_raw_topic=os.getenv("KAFKA_RAW_TOPIC", "nids.raw.packets"),
        kafka_group_id=os.getenv("KAFKA_GROUP_ID", "nids-postgres-sink"),
        kafka_client_id=os.getenv("KAFKA_CLIENT_ID", "nids-client"),
        database_url=database_url,
    )
