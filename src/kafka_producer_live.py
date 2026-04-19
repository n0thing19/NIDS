from __future__ import annotations

import argparse
import json

from dotenv import load_dotenv
from kafka import KafkaProducer
from scapy.all import sniff

from src.config import load_config
from src.packet_codec import packet_to_event


def build_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Capture live packets and publish raw events to Kafka")
    parser.add_argument("--iface", default=None, help="Network interface for packet capture")
    parser.add_argument("--count", type=int, default=0, help="Packet count limit (0 means unlimited)")
    parser.add_argument("--bpf", default=None, help="Optional BPF filter")
    return parser.parse_args()


def main() -> None:
    load_dotenv()
    args = build_args()
    cfg = load_config()

    producer = KafkaProducer(
        bootstrap_servers=cfg.kafka_bootstrap_servers,
        client_id=f"{cfg.kafka_client_id}-live-producer",
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
    )

    def _publish(packet):
        event = packet_to_event(packet, source="live_capture", interface=args.iface)
        producer.send(cfg.kafka_raw_topic, event)

    sniff(prn=_publish, store=False, iface=args.iface, filter=args.bpf, count=args.count)
    producer.flush()
    producer.close()


if __name__ == "__main__":
    main()
