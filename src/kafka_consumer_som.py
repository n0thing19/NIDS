import os
import json
import logging
import sys
from datetime import datetime, timezone

import joblib
import numpy as np
import pandas as pd
import requests
from kafka import KafkaConsumer
from dotenv import load_dotenv

from src.config import load_config
from src.db import create_connection, init_nids_tables, INSERT_ALERT_SQL

# --- Konfigurasi ---
load_dotenv()
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

MODEL_PATH = "model/nids_som_rebalanced.joblib"
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY") # Diambil dari .env
DIST_NORMAL_MIN = 0.801
LIVE_DIST_THRESHOLD = 7.5

FEATURE_COLUMNS = [
    "PROTOCOL", "L7_PROTO", "IN_BYTES", "OUT_BYTES", "IN_PKTS", "OUT_PKTS",
    "TCP_FLAGS", "CLIENT_TCP_FLAGS", "SERVER_TCP_FLAGS", "FLOW_DURATION_MILLISECONDS",
    "DURATION_IN", "DURATION_OUT", "MIN_TTL", "MAX_TTL", "LONGEST_FLOW_PKT",
    "SHORTEST_FLOW_PKT", "MIN_IP_PKT_LEN", "MAX_IP_PKT_LEN", "SRC_TO_DST_AVG_THROUGHPUT",
    "DST_TO_SRC_AVG_THROUGHPUT", "TCP_WIN_MAX_IN", "TCP_WIN_MAX_OUT"
]

_memory_cache = {}

# --- Helper Functions ---
def _is_private_ip(ip: str) -> bool:
    private_prefixes = ("10.", "192.168.", "172.16.", "172.31.", "127.", "169.254.")
    return any(ip.startswith(p) for p in private_prefixes)

def fetch_reputation(ip: str, db_conn) -> tuple:
    # 1. Abaikan IP Privat
    if _is_private_ip(ip): 
        return 0, "Private Network", "Private"
    
    # 2. Cek Memory Cache (Sangat Cepat)
    if ip in _memory_cache: 
        return _memory_cache[ip]

    # 3. Cek Database Cache (Hemat API)
    try:
        with db_conn.cursor() as cur:
            cur.execute(
                "SELECT abuse_score, isp, usage_type FROM ip_reputation_cache WHERE ip = %s", 
                (ip,)
            )
            row = cur.fetchone()
            if row:
                res = (int(row[0]), str(row[1]), str(row[2]))
                _memory_cache[ip] = res
                return res
    except Exception as e:
        log.error(f"Error checking DB cache for {ip}: {e}")

    # Jika tidak ada di DB, kita kembalikan None/Default agar Main Logic tahu harus tembak API
    return None 

def call_abuseipdb_api(ip: str, db_conn) -> tuple:
    """Fungsi khusus untuk menembak API dan menyimpan hasilnya"""
    if not ABUSEIPDB_API_KEY: 
        return 0, "No API Key", ""
    
    try:
        log.info(f"🌐 Calling AbuseIPDB API for: {ip}")
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=5
        )
        data = resp.json().get("data", {})
        abuse_score = int(data.get("abuseConfidenceScore", 0))
        isp = str(data.get("isp", ""))
        utype = str(data.get("usageType", ""))
        
        res = (abuse_score, isp, utype)
        
        # Simpan ke Database Cache agar tidak tembak API lagi nanti
        try:
            with db_conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO ip_reputation_cache (ip, abuse_score, isp, usage_type, checked_at)
                    VALUES (%s, %s, %s, %s, NOW())
                    ON CONFLICT (ip) DO UPDATE 
                    SET abuse_score = EXCLUDED.abuse_score, isp = EXCLUDED.isp, checked_at = NOW()
                """, (ip, abuse_score, isp, utype))
                db_conn.commit()
        except Exception as e:
            log.error(f"Gagal simpan cache ke DB: {e}")

        _memory_cache[ip] = res
        return res
    except Exception as e:
        log.error(f"API Error: {e}")
        return 0, "API Error", ""

def compute_metrics(dist: float) -> tuple:
    score = (dist - DIST_NORMAL_MIN) / (LIVE_DIST_THRESHOLD - DIST_NORMAL_MIN)
    anomaly_score = round(float(np.clip(score, 0.0, 1.0) * 100), 2)
    return anomaly_score, round(100.0 - anomaly_score, 2)

# --- Main Logic ---
def main():
    cfg = load_config()
    if not cfg.database_url:
        sys.exit(1)

    # Load Model
    package = joblib.load(MODEL_PATH)
    model, scaler, winner_labels = package["model"], package["scaler"], package["winner_labels"]

    # Database Setup
    conn = create_connection(cfg.database_url)
    init_nids_tables(conn)

    consumer = KafkaConsumer(
        cfg.kafka_raw_topic,
        bootstrap_servers=cfg.kafka_bootstrap_servers,
        group_id=f"{cfg.kafka_group_id}-ai-engine",
        value_deserializer=lambda v: json.loads(v.decode("utf-8"))
    )

    log.info("NIDS SOM Consumer Online...")

    try:
        for msg in consumer:
            data = msg.value
            if not isinstance(data, dict): 
                continue

            raw_features = {}
            for col in FEATURE_COLUMNS:
                val = data.get(col, 0)
                try:
                    raw_features[col] = float(val) if val is not None else 0.0
                except ValueError:
                    raw_features[col] = 0.0

            df_input = pd.DataFrame([raw_features])
            
            df_log = np.log1p(np.maximum(0, df_input))
            
            input_vec = scaler.transform(df_log)
            
            current_vector = input_vec[0]
            bmu = model.winner(current_vector)
            weights = model.get_weights()[bmu[0], bmu[1]]
            dist = np.linalg.norm(current_vector - weights)            
            
            # ---------------------------------------------------------
            # 1. PREDIKSI SOM (BEHAVIORAL)
            # ---------------------------------------------------------
            score, conf = compute_metrics(dist)
            status = "ANOMALY" if dist > LIVE_DIST_THRESHOLD else "NORMAL"
            
            # ---------------------------------------------------------
            # 2. CEK REPUTASI (THREAT INTELLIGENCE)
            # ---------------------------------------------------------
            dst_ip = data.get("dst_ip", "")
            
            # Selalu cek cache internal (Memory/Database) terlebih dahulu
            rep_data = fetch_reputation(dst_ip, conn)
            
            if rep_data is None:
                # Strategi Hemat Token: Hanya panggil API eksternal jika SOM mendeteksi keanehan
                if status == "ANOMALY":
                    abuse_score, isp, utype = call_abuseipdb_api(dst_ip, conn)
                else:
                    # Biarkan 0 jika traffic normal dan belum ada di cache untuk hemat token
                    abuse_score, isp, utype = 0, "Unchecked", ""
            else:
                # Jika sudah ada di cache (baik karena history serangan atau IP aman), gunakan datanya
                abuse_score, isp, utype = rep_data

            # ---------------------------------------------------------
            # 3. PENENTUAN TINGKAT RISIKO (RISK MATRIX)
            # ---------------------------------------------------------
            if status == "ANOMALY" and abuse_score > 0:
                # Perilaku aneh + Reputasi buruk = Blokir Langsung
                risk = "CRITICAL"
                
            elif status == "ANOMALY" and abuse_score == 0:
                # Perilaku aneh + Reputasi bersih = Investigasi Analis (Potensi Zero-Day)
                risk = "HIGH"
                
            elif status == "NORMAL" and abuse_score > 0:
                # Perilaku biasa saja + Reputasi buruk = Pengintaian / Reconnaissance
                risk = "MEDIUM"
                
            else:
                # Perilaku biasa saja + Reputasi bersih = Aman
                risk = "LOW"

            # ---------------------------------------------------------
            # 4. SIMPAN KE DATABASE
            # ---------------------------------------------------------
            with conn, conn.cursor() as cur:
                cur.execute(INSERT_ALERT_SQL, (
                    data.get("captured_at"), data.get("src_ip"), dst_ip,
                    data.get("application_name"), status, risk, score, conf, 
                    round(dist, 4), int(bmu[0]), int(bmu[1]),
                    int(data.get("IN_BYTES", 0)), int(data.get("OUT_BYTES", 0)),
                    int(data.get("PROTOCOL", 0)), abuse_score, isp, utype
                ))
            
            log.info(f"Processed: {data.get('src_ip')} -> {dst_ip} | Status: {status} | Risk: {risk} | AbuseScore: {abuse_score}")

    except KeyboardInterrupt:
        pass
    finally:
        conn.close()

if __name__ == "__main__":
    main()