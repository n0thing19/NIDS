import json
import time
import logging
from datetime import datetime, timezone
from dotenv import load_dotenv
from kafka import KafkaProducer

from src.config import load_config

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

def create_base_packet(src_ip, app_name):
    """Membuat template dasar paket jaringan"""
    return {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "src_ip": src_ip,
        "dst_ip": "192.168.1.100",
        "application_name": app_name,
        "PROTOCOL": 6.0, "L7_PROTO": 0.0,
        "IN_BYTES": 500.0, "OUT_BYTES": 500.0,
        "IN_PKTS": 5.0, "OUT_PKTS": 5.0,
        "TCP_FLAGS": 0.0, "CLIENT_TCP_FLAGS": 0.0, "SERVER_TCP_FLAGS": 0.0,
        "FLOW_DURATION_MILLISECONDS": 100.0, "DURATION_IN": 50.0, "DURATION_OUT": 50.0,
        "MIN_TTL": 64.0, "MAX_TTL": 64.0,
        "LONGEST_FLOW_PKT": 100.0, "SHORTEST_FLOW_PKT": 100.0,
        "MIN_IP_PKT_LEN": 40.0, "MAX_IP_PKT_LEN": 1500.0,
        "SRC_TO_DST_AVG_THROUGHPUT": 1000.0, "DST_TO_SRC_AVG_THROUGHPUT": 1000.0,
        "TCP_WIN_MAX_IN": 8192.0, "TCP_WIN_MAX_OUT": 8192.0
    }

def main():
    load_dotenv()
    cfg = load_config()

    producer = KafkaProducer(
        bootstrap_servers=cfg.kafka_bootstrap_servers,
        client_id=f"{cfg.kafka_client_id}-multi-attack-tester",
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
    )

    log.info("Memulai simulasi MULTIPLE ATTACKS ke topik: %s", cfg.kafka_raw_topic)
    print("=" * 60)

    # ---------------------------------------------------------
    # 1. SERANGAN VOLUMETRIK: UDP Flood (DDoS)
    # Karakteristik: Banyak sekali paket UDP kecil dalam waktu sangat singkat
    # ---------------------------------------------------------
    udp_flood = create_base_packet("10.10.10.11", "UDP_Flood_DDoS")
    udp_flood.update({
        "PROTOCOL": 17.0, # UDP
        "IN_BYTES": 9000000.0, "OUT_BYTES": 0.0,
        "IN_PKTS": 150000.0, "OUT_PKTS": 0.0,
        "FLOW_DURATION_MILLISECONDS": 5.0, # Sangat singkat
        "LONGEST_FLOW_PKT": 60.0, "SHORTEST_FLOW_PKT": 60.0, # Ukuran paket seragam
        "SRC_TO_DST_AVG_THROUGHPUT": 99999999.0
    })

    # ---------------------------------------------------------
    # 2. SERANGAN STEALTH: SYN Port Scan (Nmap)
    # Karakteristik: Cek port terbuka menggunakan TCP SYN, tanpa membalas
    # ---------------------------------------------------------
    syn_scan = create_base_packet("10.10.10.22", "Nmap_SYN_Scan")
    syn_scan.update({
        "PROTOCOL": 6.0, # TCP
        "TCP_FLAGS": 2.0, # 2 = SYN Flag
        "CLIENT_TCP_FLAGS": 2.0,
        "IN_BYTES": 44.0, "OUT_BYTES": 0.0, # Sangat kecil
        "IN_PKTS": 1.0, "OUT_PKTS": 0.0,
        "FLOW_DURATION_MILLISECONDS": 0.0, # Terjadi instan
        "MIN_TTL": 255.0 # Biasanya Nmap menggunakan TTL aneh
    })

    # ---------------------------------------------------------
    # 3. SERANGAN DATA LEAK: Exfiltration (Pencurian Data)
    # Karakteristik: Koneksi berdurasi lama, rasio upload jauh lebih besar dari download
    # ---------------------------------------------------------
    data_leak = create_base_packet("10.10.10.33", "Data_Exfiltration")
    data_leak.update({
        "IN_BYTES": 1500.0,          # Request kecil dari hacker
        "OUT_BYTES": 8500000000.0,   # Server mengirim data raksasa keluar (Bocor)
        "IN_PKTS": 10.0, "OUT_PKTS": 500000.0,
        "FLOW_DURATION_MILLISECONDS": 3600000.0, # Berjalan selama 1 jam
        "DST_TO_SRC_AVG_THROUGHPUT": 85000000.0
    })

    # ---------------------------------------------------------
    # 4. SERANGAN RESOURCE EXHAUSTION: Slowloris (Slow HTTP)
    # Karakteristik: TCP tersambung sangat lama, mengirim data sepotong demi sepotong
    # ---------------------------------------------------------
    slowloris = create_base_packet("10.10.10.44", "Slowloris_Attack")
    slowloris.update({
        "PROTOCOL": 6.0, "L7_PROTO": 7.0, # HTTP
        "IN_BYTES": 300.0, "OUT_BYTES": 300.0,
        "IN_PKTS": 5.0, "OUT_PKTS": 5.0,
        "FLOW_DURATION_MILLISECONDS": 900000.0, # Sangat lama menahan koneksi
        "SRC_TO_DST_AVG_THROUGHPUT": 0.1 # Throughput sangat lambat (ciri khas slowloris)
    })

    attacks = [
        ("UDP Flood", udp_flood),
        ("Port Scan", syn_scan),
        ("Data Exfiltration", data_leak),
        ("Slowloris", slowloris)
    ]

    try:
        for name, packet in attacks:
            log.info(f"Menembakkan serangan: [{name}] dari IP {packet['src_ip']}...")
            # Update timestamp agar selalu baru saat dikirim
            packet["captured_at"] = datetime.now(timezone.utc).isoformat()
            
            producer.send(cfg.kafka_raw_topic, packet)
            producer.flush()
            
            # Beri jeda 3 detik tiap serangan agar terlihat di grafik timeline Dashboard
            time.sleep(3)
            
        print("=" * 60)
        log.info("Semua simulasi serangan selesai dikirim!")
        log.info("Periksa Terminal Consumer dan Dashboard Streamlit Anda.")
    except Exception as e:
        log.error("Gagal mengirim simulasi: %s", e)
    finally:
        producer.close()

if __name__ == "__main__":
    main()