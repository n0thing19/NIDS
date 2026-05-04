from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone

import joblib
import numpy as np
import pandas as pd
from kafka import KafkaConsumer

from src.config import load_config
from src.db import create_connection 

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

MODEL_PATH = "model/nids_som_rebalanced.joblib"

FEATURE_COLUMNS = [
    "PROTOCOL", "L7_PROTO",
    "IN_BYTES", "OUT_BYTES",
    "IN_PKTS", "OUT_PKTS",
    "TCP_FLAGS", "CLIENT_TCP_FLAGS", "SERVER_TCP_FLAGS",
    "FLOW_DURATION_MILLISECONDS", "DURATION_IN", "DURATION_OUT",
    "MIN_TTL", "MAX_TTL",
    "LONGEST_FLOW_PKT", "SHORTEST_FLOW_PKT", "MIN_IP_PKT_LEN", "MAX_IP_PKT_LEN",
    "SRC_TO_DST_AVG_THROUGHPUT", "DST_TO_SRC_AVG_THROUGHPUT",
    "TCP_WIN_MAX_IN", "TCP_WIN_MAX_OUT",
]


# UPDATE: Menambahkan kolom som_x dan som_y untuk visualisasi map
CREATE_ALERTS_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS nids_alerts (
    id BIGSERIAL PRIMARY KEY,
    captured_at TIMESTAMPTZ NOT NULL,
    src_ip TEXT,
    dst_ip TEXT,
    application TEXT,
    status TEXT,
    accuracy_percent REAL,
    distance REAL,
    som_x INTEGER,
    som_y INTEGER,
    in_bytes BIGINT,
    out_bytes BIGINT,
    protocol INTEGER,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"""

# UPDATE: Menambahkan placeholder untuk som_x dan som_y
INSERT_ALERT_SQL = """
INSERT INTO nids_alerts (
    captured_at, src_ip, dst_ip, application, status,
    accuracy_percent, distance, som_x, som_y, in_bytes, out_bytes, protocol
) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
"""


def load_model_package(path: str) -> tuple:
    """Load model, scaler, dan winner_labels. Raise jika gagal."""
    log.info("Memuat paket NIDS SOM dari %s ...", path)
    try:
        package = joblib.load(path)
        model = package["model"]
        scaler = package["scaler"]
        winner_labels = package["winner_labels"]
        log.info("Model dan Scaler berhasil dimuat.")
        return model, scaler, winner_labels
    except Exception as exc:
        log.critical("Gagal memuat model: %s", exc)
        raise


def get_prediction(winner_labels, bmu: tuple) -> int:
    """Ambil label prediksi dari BMU secara aman."""
    if isinstance(winner_labels, dict):
        return winner_labels.get(bmu, 0)
    try:
        return winner_labels[bmu[0]][bmu[1]]
    except (IndexError, KeyError, TypeError):
        return 0


def extract_features(packet_data: dict) -> np.ndarray:
    """Ekstrak dan transformasi fitur dari raw packet dict."""
    raw_vals = []
    for col in FEATURE_COLUMNS:
        val = packet_data.get(col, 0)
        val = float(val) if val is not None else 0.0
        
        # 3. KUNCI PERBAIKAN: Di training, np.log1p diterapkan ke SEMUA fitur
        # Tambahkan max(0.0, val) untuk berjaga-jaga jika ada paket bernilai negatif
        val = np.log1p(max(0.0, val))
        
        raw_vals.append(val)
        
    arr = np.array(raw_vals, dtype=np.float64)
    # 4. Mirroring pembersihan NaN/Infinity yang dilakukan di proses training
    arr = np.nan_to_num(arr, nan=0.0, posinf=1.0, neginf=-1.0)
    
    return arr


def compute_accuracy(dist: float, dist_ref: float) -> float:
    """
    Hitung confidence score berdasarkan jarak Euclidean ke BMU.
    dist_ref = nilai referensi (misal rata-rata dist saat training).
    Semakin kecil dist → semakin tinggi confidence.
    """
    return float(np.exp(-dist / dist_ref) * 100)


def main() -> None:
    cfg = load_config()

    if not cfg.database_url:
        log.critical("DATABASE_URL atau variabel PGHOST dkk belum diatur di .env!")
        sys.exit(1)

    model, scaler, winner_labels = load_model_package(MODEL_PATH)
    dist_ref = 1000.0  

    # 1. Inisialisasi Database PostgreSQL
    log.info("Menghubungkan ke PostgreSQL...")
    db_conn = create_connection(cfg.database_url)
    with db_conn, db_conn.cursor() as cur:
        cur.execute(CREATE_ALERTS_TABLE_SQL)
    log.info("Tabel 'nids_alerts' siap digunakan.")

    # 2. Inisialisasi Consumer Kafka
    consumer = KafkaConsumer(
        cfg.kafka_raw_topic,
        bootstrap_servers=cfg.kafka_bootstrap_servers,
        group_id=f"{cfg.kafka_group_id}-ai-engine",
        auto_offset_reset="latest",
        value_deserializer=lambda v: json.loads(v.decode("utf-8")),
    )

    log.info("Mesin AI Online. Memantau: %s | DB Aktif", cfg.kafka_raw_topic)
    header = f"{'TIME':<10} | {'SOURCE IP':<15} | {'STATUS':<10} | {'ACCURACY':<10} | DIST"
    print("-" * 95)
    print(header)
    print("-" * 95)

    try:
        for msg in consumer:
            packet_data = msg.value

            if not isinstance(packet_data, dict):
                continue

            try:
                # Ekstraksi fitur
                raw_vector = extract_features(packet_data)
                df_input = pd.DataFrame([raw_vector], columns=FEATURE_COLUMNS)
                scaled_vals = scaler.transform(df_input)
                input_vector = scaled_vals[0]

                # Inferensi SOM
                bmu = model.winner(input_vector) # Hasil bmu adalah tuple (x, y)
                weights = model.get_weights()[bmu[0], bmu[1]]
                dist = float(np.linalg.norm(input_vector - weights))

                accuracy = compute_accuracy(dist, dist_ref)
                prediction = get_prediction(winner_labels, bmu)

                # Output & Setup Variabel Database
                # Tambahkan ini di atasnya (Anda bebas menyesuaikan angkanya, saya sarankan 2.5 hingga 3.0)
                DISTANCE_THRESHOLD = 2.5 

                # Ubah baris status_str menjadi ini:
                status_str = "ANOMALY" if (prediction == 1) or (dist > DISTANCE_THRESHOLD) else "NORMAL"                
                color = "\033[91m" if status_str == "ANOMALY" else "\033[92m"
                src_ip = packet_data.get("src_ip", "?.?.?.?")
                dst_ip = packet_data.get("dst_ip", "?.?.?.?")
                app_name = packet_data.get("application_name", "Unknown")
                
                # Menggunakan timestamp bawaan packet jika ada
                captured_at = packet_data.get("captured_at", datetime.now(timezone.utc).isoformat())
                ts_display = datetime.now().strftime("%H:%M:%S")

                # 3. Simpan Deteksi ke PostgreSQL (Termasuk koordinat SOM x, y)
                try:
                    with db_conn, db_conn.cursor() as cur:
                        cur.execute(
                            INSERT_ALERT_SQL,
                            (
                                captured_at,
                                src_ip,
                                dst_ip,
                                app_name,
                                status_str,
                                round(accuracy, 2),
                                round(dist, 4),
                                int(bmu[0]), # som_x
                                int(bmu[1]), # som_y
                                int(packet_data.get("IN_BYTES", 0)),
                                int(packet_data.get("OUT_BYTES", 0)),
                                int(packet_data.get("PROTOCOL", 0))
                            )
                        )
                except Exception as db_exc:
                    log.error("Gagal menyimpan ke PostgreSQL: %s", db_exc)

                # 4. Print Log Terminal
                if status_str == "ANOMALY":
                    app_short = (app_name[:10] + "..") if len(app_name) > 10 else app_name
                    in_bytes = packet_data.get("IN_BYTES", 0)
                    print(
                        f"[{ts_display}] | {src_ip:<15} | {color}{status_str:<10}\033[0m "
                        f"| {accuracy:>8.2f}% | Dist: {dist:.4f} "
                        f"| BMU: ({bmu[0]},{bmu[1]}) | App: {app_short:<12}"
                    )
                else:
                    print(
                        f"[{ts_display}] | {src_ip:<15} | {color}{status_str:<10}\033[0m "
                        f"| {accuracy:>8.2f}% | Dist: {dist:.4f} | BMU: ({bmu[0]},{bmu[1]})"
                    )

            except Exception as exc:
                log.error("Error memproses pesan: %s", exc)

    except KeyboardInterrupt:
        log.info("Dihentikan oleh user.")
    finally:
        consumer.close()
        db_conn.close()
        log.info("Consumer Kafka dan Koneksi Database ditutup.")


if __name__ == "__main__":
    main()