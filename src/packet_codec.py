from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict

from scapy.all import Packet, Raw


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_packet_show(packet: Packet) -> str:
    try:
        return packet.show(dump=True)
    except Exception:
        return "<packet show unavailable>"


def packet_to_event(packet: Packet, *, source: str, interface: str | None = None) -> Dict[str, Any]:
    raw_bytes = bytes(packet)

    return {
        "source": source,
        "captured_at": _utc_now_iso(),
        "interface": interface,
        "packet_len": len(raw_bytes),
        "packet_hex": raw_bytes.hex(),
        "packet_summary": packet.summary(),
        "layers": [layer.__name__ for layer in packet.layers()],
        "decode": _safe_packet_show(packet),
        "has_raw_payload": packet.haslayer(Raw),
    }
