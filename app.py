from __future__ import annotations

from sklearn.metrics import accuracy_score, classification_report
import streamlit as st
import psycopg2
import pandas as pd
from datetime import datetime
import altair as alt
import joblib
import numpy as np
import os

# Mengatur opsi render pandas agar tidak membebani memori browser
pd.set_option("styler.render.max_elements", 5000000)

st.set_page_config(page_title="NIDS Dashboard", layout="wide", page_icon="🛡️")

# --- KONFIGURASI DATABASE DINAMIS ---
# Memperbaiki pembacaan DB_HOST agar default ke localhost jika tidak ada di .env
DB_HOST = os.environ.get("DB_HOST", "localhost") 
DB_PORT = os.environ.get("DB_PORT", "5432")
DB_NAME = os.environ.get("PGDATABASE", "nids")
DB_USER = os.environ.get("PGUSER", "postgres")
DB_PASS = os.environ.get("PGPASSWORD", "postgres")

FEATURE_COLUMNS = [
    "PROTOCOL", "L7_PROTO", "IN_BYTES", "OUT_BYTES", "IN_PKTS", "OUT_PKTS",
    "TCP_FLAGS", "CLIENT_TCP_FLAGS", "SERVER_TCP_FLAGS",
    "FLOW_DURATION_MILLISECONDS", "DURATION_IN", "DURATION_OUT",
    "MIN_TTL", "MAX_TTL", "LONGEST_FLOW_PKT", "SHORTEST_FLOW_PKT",
    "MIN_IP_PKT_LEN", "MAX_IP_PKT_LEN", "SRC_TO_DST_AVG_THROUGHPUT",
    "DST_TO_SRC_AVG_THROUGHPUT", "TCP_WIN_MAX_IN", "TCP_WIN_MAX_OUT"
]

st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap');
    html, body, [class*="css"] { font-family: 'Rajdhani', sans-serif; }
    .stApp { background-color: #0a0e1a; color: #e0e6f0; }
    h1, h2, h3 { font-family: 'Share Tech Mono', monospace !important; color: #00f0ff !important; }
    .metric-card { background: linear-gradient(135deg, #0d1b2a, #112240); border: 1px solid #00f0ff33; border-radius: 12px; padding: 1.5rem 2rem; text-align: center; margin-bottom: 1rem; }
    .metric-label { font-family: 'Share Tech Mono', monospace; font-size: 0.85rem; color: #7a9fc0; text-transform: uppercase; }
    .metric-value { font-family: 'Share Tech Mono', monospace; font-size: 2.5rem; font-weight: bold; }
    .metric-flow { color: #00f0ff; }
    .metric-anomaly { color: #ff4b6e; }
    .section-title { font-family: 'Share Tech Mono', monospace; color: #00f0ff; border-left: 3px solid #00f0ff; padding-left: 0.75rem; margin: 1.5rem 0 1rem 0; }
    .stTabs [data-baseweb="tab-list"] { gap: 2rem; }
    .stTabs [data-baseweb="tab"] { font-family: 'Share Tech Mono', monospace; font-size: 1.1rem; padding: 1rem 0; }
</style>
""", unsafe_allow_html=True)

st.markdown("# 🛡️ NIDS — Network Intrusion Detection")
st.markdown(f"**Connected to:** `{DB_NAME}` on `{DB_HOST}`")
st.markdown("---")

# --- FUNGSI HELPER UI ---
def highlight_risk(val):
    """Fungsi untuk mewarnai baris tabel berdasarkan Risk Level"""
    val_str = str(val).upper()
    if val_str == 'CRITICAL':
        return 'background-color: #5c0016; color: #ff99aa; font-weight: bold;'
    elif val_str == 'HIGH':
        return 'background-color: #5c3300; color: #ffcc99;'
    elif val_str == 'MEDIUM':
        return 'background-color: #5c4d00; color: #ffe699;'
    return '' # LOW / NORMAL

# --- FUNGSI LOAD DATA & MODEL ---
@st.cache_resource
def load_som_package():
    try:
        model_path = 'model/nids_som_rebalanced.joblib' 
        if os.path.exists(model_path):
            return joblib.load(model_path)
        return None
    except Exception as e:
        st.error(f"Gagal memuat paket SOM: {e}")
        return None

@st.cache_data(ttl=2)
def load_db_data():
    try:
        conn = psycopg2.connect(
            host=DB_HOST, port=DB_PORT, dbname=DB_NAME, 
            user=DB_USER, password=DB_PASS, connect_timeout=5
        )

        query = """
            SELECT * FROM nids_alerts 
            ORDER BY captured_at DESC
        """
        df = pd.read_sql(query, conn)
        conn.close()
        return df
    except Exception as e:
        return str(e)

def create_som_chart(df_traffic, som_model):
    if som_model is None or df_traffic is None or df_traffic.empty:
        return None
    try:
        u_matrix = som_model.distance_map()
    except Exception:
        return None

    um_data = [{'som_x': i, 'som_y': j, 'distance': float(u_matrix[i, j])} 
               for i in range(u_matrix.shape[0]) for j in range(u_matrix.shape[1])]
    um_df = pd.DataFrame(um_data)

    background = alt.Chart(um_df).mark_rect(cornerRadius=2).encode(
        x=alt.X('som_x:O', title='SOM X', axis=alt.Axis(labelAngle=0)),
        y=alt.Y('som_y:O', title='SOM Y', sort='descending'),
        color=alt.Color('distance:Q', scale=alt.Scale(scheme='greys', reverse=True), legend=None),
        tooltip=[alt.Tooltip('distance:Q', title='Jarak U-Matrix')]
    )

    traffic_grouped = df_traffic.groupby(['som_x', 'som_y', 'status']).size().reset_index(name='count')
    
    foreground = alt.Chart(traffic_grouped).mark_circle(opacity=0.85, stroke='black', strokeWidth=1).encode(
        x=alt.X('som_x:O'),
        y=alt.Y('som_y:O', sort='descending'),
        size=alt.Size('count:Q', scale=alt.Scale(range=[30, 800]), title='Volume Paket'),
        color=alt.Color('status:N', scale=alt.Scale(domain=['NORMAL', 'ANOMALY'], range=['#00f0ff', '#ff4b6e']), title="Status"),
        tooltip=['som_x', 'som_y', 'status', 'count']
    )
    return (background + foreground).properties(height=380)

@st.fragment(run_every=5)
def render_realtime_tab(som_package):
    df = load_db_data()
    som_model = som_package.get('model') if som_package else None
    
    if isinstance(df, str):
        st.error(f"❌ Gagal koneksi ke Database ({DB_HOST})")
        st.info(f"Detail: {df}")
        return

    if df is None or df.empty:
        st.info("📡 Koneksi Berhasil. Menunggu aliran data dari Kafka Producer & AI Engine...")
        return

    total_flow = len(df)
    total_anomaly = df["status"].str.upper().str.contains("ANOMALY", na=False).sum()

    # --- TOP METRICS ---
    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown(f'<div class="metric-card"><div class="metric-label">Total Traffic Processed</div><div class="metric-value metric-flow">{total_flow:,}</div></div>', unsafe_allow_html=True)
    with c2:
        st.markdown(f'<div class="metric-card"><div class="metric-label">Detected Anomalies</div><div class="metric-value metric-anomaly">{total_anomaly:,}</div></div>', unsafe_allow_html=True)
    with c3:
        health = ((total_flow - total_anomaly) / total_flow) * 100 if total_flow > 0 else 100
        st.markdown(f'<div class="metric-card"><div class="metric-label">Network Health</div><div class="metric-value" style="color: #00f0ff;">{health:.1f}%</div></div>', unsafe_allow_html=True)

    # --- MIDDLE ROW: TIMELINE & SOM MAP ---
    col_chart1, col_chart2 = st.columns(2)
    with col_chart1:
        st.markdown('<div class="section-title">📈 Flow vs Anomaly (Timeline)</div>', unsafe_allow_html=True)
        chart_data = df.copy()
        chart_data["captured_at"] = pd.to_datetime(chart_data["captured_at"], utc=True)
        chart_data = chart_data.set_index("captured_at")
        
        total_flow_ts = chart_data.resample("1min").size().rename("Total Flow")
        anomaly_ts = chart_data[chart_data["status"].str.upper().str.contains("ANOMALY", na=False)].resample("1min").size().rename("Total Anomaly")
        time_df = pd.concat([total_flow_ts, anomaly_ts], axis=1).fillna(0)
        st.line_chart(time_df, color=["#00f0ff", "#ff4b6e"], height=380)

    with col_chart2:
        st.markdown('<div class="section-title">🗺️ U-Matrix Topology Map</div>', unsafe_allow_html=True)
        if som_model:
            chart = create_som_chart(df, som_model)
            if chart: st.altair_chart(chart, use_container_width=True)
        else:
            st.warning("Model SOM tidak ditemukan.")

    # --- BOTTOM ROW: ALERTS TABLE ---
    st.markdown('<div class="section-title">🚨 Recent Anomaly Logs</div>', unsafe_allow_html=True)
    anomaly_logs = df[df["status"].str.upper().str.contains("ANOMALY", na=False)].head(100)
    
    if not anomaly_logs.empty:
        # Mengatur urutan kolom agar kolom utama tampil paling kiri
        important_cols = [
            "captured_at", "src_ip", "dst_ip", "status", 
            "risk_zone", "distance", "isp", "usage_type"
        ]
        
        # Filter memastikan kolom tidak error jika tidak ada di DB
        valid_important_cols = [c for c in important_cols if c in anomaly_logs.columns]
        other_cols = [c for c in anomaly_logs.columns if c not in valid_important_cols]
        final_col_order = valid_important_cols + other_cols
        
        st.dataframe(
            anomaly_logs.style.map(
                highlight_risk, subset=['risk_zone'] if 'risk_zone' in anomaly_logs.columns else []
            ),
            use_container_width=True, 
            hide_index=True, 
            height=380,
            column_order=final_col_order
        )
    else:
        st.success("✅ **Jaringan saat ini aman.** Tidak ada aktivitas anomali yang terdeteksi.")
        
    st.caption(f"Last sync: {datetime.now().strftime('%H:%M:%S')} (Auto-refresh 5s)")

def process_offline_csv(df_csv, package, threshold, target_column=None):
    st.info(f"Memproses dataset dengan Hybrid Logic (Threshold: {threshold})...")
    
    for col in FEATURE_COLUMNS:
        if col not in df_csv.columns:
            df_csv[col] = 0.0
            
    X_raw = df_csv[FEATURE_COLUMNS].values.astype(float)
    X_log = np.log1p(np.maximum(0.0, X_raw))
    X_clean = np.nan_to_num(X_log, nan=0.0)
    
    scaler = package['scaler']
    X_scaled = scaler.transform(X_clean)
    som = package['model']
    winner_labels = package.get('winner_labels', {})
    
    results = []
    y_pred = [] 
    progress_bar = st.progress(0)
    total_rows = len(X_scaled)
    
    for i, x in enumerate(X_scaled):
        bmu = som.winner(x)
        weights = som.get_weights()[bmu[0], bmu[1]]
        dist = float(np.linalg.norm(x - weights))
        
        # Ambil identitas neuron (1 jika neuron ini dibentuk oleh serangan saat training)
        pred_label = winner_labels.get(bmu, 0) if isinstance(winner_labels, dict) else winner_labels[bmu[0]][bmu[1]]
        
        # --- LOGIKA HYBRID ---
        is_anomaly = (dist > threshold) or (pred_label == 1)
        
        pred_val = 1 if is_anomaly else 0
        y_pred.append(pred_val)
            
        results.append({
            'som_x': int(bmu[0]),
            'som_y': int(bmu[1]),
            'distance': round(dist, 4),
            'status': 'ANOMALY' if is_anomaly else 'NORMAL'
        })
        
        if i % (max(1, total_rows // 20)) == 0:
            progress_bar.progress(min(1.0, i / total_rows))
            
    progress_bar.progress(1.0)
    df_results = pd.DataFrame(results)
    final_df = pd.concat([df_csv.reset_index(drop=True), df_results], axis=1)

    if target_column and target_column in df_csv.columns:
        # Konversi langsung ke integer karena label dipastikan berisi 0 atau 1
        y_true = df_csv[target_column].fillna(0).astype(int).values
        acc = accuracy_score(y_true, y_pred)
        st.success(f"Akurasi Model pada Uji Offline: {acc:.2%}")
        
        with st.expander("Lihat Detail Laporan Klasifikasi"):
            report = classification_report(y_true, y_pred, target_names=['NORMAL', 'ANOMALY'], output_dict=True)
            st.table(pd.DataFrame(report).transpose())

    return final_df

# --- EXECUTION ---
package = load_som_package()
tab1, tab2 = st.tabs(["🔴 Real-Time Monitoring", "📂 Offline Demo (CSV)"])

with tab1:
    render_realtime_tab(package)

with tab2:
    st.markdown("### Uji Deteksi Zero-Day via File CSV")
    uploaded_file = st.file_uploader("Unggah File CSV Traffic", type=['csv'])
    
    if uploaded_file is not None and package:
        df_offline = pd.read_csv(uploaded_file)
        st.markdown("---")
        
        col_setup1, col_setup2 = st.columns([2, 1])
        
        with col_setup1:
            st.info("💡 **Opsional:** Pilih kolom label asli jika Anda ingin melihat akurasi deteksi.")
            default_index = 0
            if 'label' in df_offline.columns:
                default_index = list(df_offline.columns).index('label')
            
            target_col = st.selectbox(
                "Pilih Kolom Target (Ground Truth):", 
                options=[None] + list(df_offline.columns),
                index=default_index + 1 if 'label' in df_offline.columns else 0,
                help="Kolom ini digunakan untuk membandingkan hasil prediksi AI dengan label asli."
            )
            
        with col_setup2:
            st.info("🎚️ **Simulasi Threshold:** Sesuaikan batas wajar jarak anomali (Zero-day limit).")
            # Slider interaktif untuk mencari threshold terbaik
            test_threshold = st.slider(
                "Distance Threshold", 
                min_value=3.0, max_value=15.0, value=6.0, step=0.1,
                help="Angka ini mensimulasikan variabel LIVE_DIST_THRESHOLD di Kafka Engine."
            )

        if st.button("🚀 Proses Analisis SOM", use_container_width=True):
            df_result = process_offline_csv(df_offline, package, threshold=test_threshold, target_column=target_col)
            
            st.markdown("### 📊 Hasil Analisis")
            c1, c2, c3 = st.columns(3)
            
            total_data = len(df_result)
            total_anom = len(df_result[df_result['status'] == 'ANOMALY'])
            
            c1.metric("Total Paket", f"{total_data:,}")
            c2.metric("Anomali Terdeteksi", f"{total_anom:,}", 
                      delta=f"{(total_anom/total_data)*100:.1f}% dari total", delta_color="inverse")
            
            if target_col and target_col in df_result.columns:
                # Konversi langsung ke integer karena label dipastikan berisi 0 atau 1
                y_true = df_result[target_col].fillna(0).astype(int).values
                y_pred = df_result['status'].apply(lambda x: 1 if x == 'ANOMALY' else 0).values
                acc = accuracy_score(y_true, y_pred)
                c3.metric("Akurasi Deteksi", f"{acc:.2%}")
            
            else:
                c3.metric("Akurasi Deteksi", "N/A", help="Pilih kolom target untuk menghitung akurasi")

                st.markdown('<div class="section-title">🗺️ U-Matrix Projection</div>', unsafe_allow_html=True)
                st.altair_chart(create_som_chart(df_result, package['model']), use_container_width=True)
                
                st.markdown('<div class="section-title">📄 Data Hasil Prediksi (Preview 1000 Baris)</div>', unsafe_allow_html=True)
                st.dataframe(
                    df_result.head(1000).style.map(
                        lambda x: 'background-color: #4a1924; color: #ffb3c1;' if x == 'ANOMALY' else '', 
                        subset=['status']
                    ),
                    use_container_width=True
                )