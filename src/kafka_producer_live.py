from __future__ import annotations

import argparse
import json
import logging
from datetime import datetime, timezone
import sys

from dotenv import load_dotenv
from kafka import KafkaProducer
from kafka.errors import KafkaError
from nfstream import NFStreamer, NFPlugin

from src.config import load_config
from src.feature_mapper import map_nfstream_to_som_features
from src.interface_selector import select_interface


logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

class TTLCollector(NFPlugin):
    def on_init(self, packet, flow):
        try:
            flow.udps.ttl = packet.ip_packet[8]
        except (IndexError, TypeError):
            flow.udps.ttl = 0

    def on_update(self, packet, flow):
        # Update hanya jika TTL sebelumnya 0 (belum berhasil diambil)
        if flow.udps.ttl == 0:
            try:
                flow.udps.ttl = packet.ip_packet[8]
            except (IndexError, TypeError):
                pass


def build_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Capture live flows using NFStream and publish to Kafka"
    )
    parser.add_argument("--iface", default=None, help="Network interface (kosongkan untuk memunculkan menu pilihan)")
    return parser.parse_args()


def main() -> None:
    load_dotenv()
    args = build_args()
    cfg = load_config()
    iface_to_use = select_interface(args.iface)
    
    producer = KafkaProducer(
        bootstrap_servers=cfg.kafka_bootstrap_servers,
        client_id=f"{cfg.kafka_client_id}-nfstream-producer",
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
    )

    streamer = NFStreamer(
        source=iface_to_use,
        promiscuous_mode=True,
        active_timeout=10,
        idle_timeout=5,
        statistical_analysis=True,
        accounting_mode=1,
        udps=TTLCollector(),
    )

    log.info("NFStreamer mulai menyadap jaringan di interface [%s]...", iface_to_use)

    try:
        for flow in streamer:
            features = map_nfstream_to_som_features(flow)
            try:
                producer.send(cfg.kafka_raw_topic, features)
            except KafkaError as exc:
                log.error("Gagal kirim ke Kafka: %s", exc)
                continue

            log.info(
                "Flow Sent: %s -> %s | TTL: %s | Flags: %s (%s)",
                features["src_ip"],
                features["dst_ip"],
                features["MIN_TTL"],
                features["TCP_FLAGS"],
                features["application_name"],
            )
    except KeyboardInterrupt:
        log.info("Stopping producer...")
    finally:
        producer.flush()
        producer.close()
        log.info("Producer ditutup.")


if __name__ == "__main__":
    main()