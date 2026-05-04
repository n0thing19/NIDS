import streamlit as st
import psycopg2
import pandas as pd
from datetime import datetime
import altair as alt
import joblib
import numpy as np
import os
import io

pd.set_option("styler.render.max_elements", 5000000)

st.set_page_config(page_title="NIDS Dashboard", layout="wide", page_icon="🛡️")

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
st.markdown("---")

# --- FUNGSI LOAD DATA & MODEL ---
@st.cache_resource
def load_som_package():
    """Memuat seluruh paket model (MiniSom, Scaler, Winner Labels)"""
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
            host="localhost", port=5432,
            dbname="nids", user="postgres", password="postgres"
        )
        query = """
            SELECT id, captured_at, status, src_ip, dst_ip, application, accuracy_percent, distance, som_x, som_y 
            FROM nids_alerts 
            ORDER BY captured_at DESC
        """
        df = pd.read_sql(query, conn)
        conn.close()
        return df
    except Exception as e:
        return None

def create_som_chart(df_traffic, som_model):
    """Membuat grafik U-Matrix + Bubble overlay secara dinamis."""
    if som_model is None or df_traffic is None or df_traffic.empty:
        return None

    u_matrix = som_model.distance_map()
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
    traffic_grouped['color'] = traffic_grouped['status'].apply(lambda x: '#ff4b6e' if 'anomaly' in x.lower() else '#00f0ff')

    foreground = alt.Chart(traffic_grouped).mark_circle(opacity=0.85, stroke='black', strokeWidth=1).encode(
        x=alt.X('som_x:O'),
        y=alt.Y('som_y:O', sort='descending'),
        size=alt.Size('count:Q', scale=alt.Scale(range=[30, 800]), title='Volume Paket'),
        color=alt.Color('color:N', scale=None),
        tooltip=[
            alt.Tooltip('som_x:O', title='SOM X'),
            alt.Tooltip('som_y:O', title='SOM Y'),
            alt.Tooltip('status:N', title='Status'),
            alt.Tooltip('count:Q', title='Jumlah Paket')
        ]
    )

    return (background + foreground).properties(height=380)

@st.fragment(run_every=5)
def render_realtime_tab(som_package):
    df = load_db_data()
    som_model = som_package.get('model') if som_package else None
    
    if df is None or df.empty:
        st.info("Menunggu aliran data dari Kafka & Database PostgreSQL...")
        return

    total_flow = len(df)
    total_anomaly = df["status"].str.lower().str.contains("anomaly", na=False).sum()

    # Metrics
    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown(f'<div class="metric-card"><div class="metric-label">Total Traffic Processed</div><div class="metric-value metric-flow">{total_flow:,}</div></div>', unsafe_allow_html=True)
    with c2:
        st.markdown(f'<div class="metric-card"><div class="metric-label">Detected Anomalies</div><div class="metric-value metric-anomaly">{total_anomaly:,}</div></div>', unsafe_allow_html=True)
    with c3:
        normal_pct = 100 if total_flow == 0 else ((total_flow - total_anomaly) / total_flow) * 100
        st.markdown(f'<div class="metric-card"><div class="metric-label">Network Health</div><div class="metric-value" style="color: #00f0ff;">{normal_pct:.1f}%</div></div>', unsafe_allow_html=True)

    # Layout Sejajar untuk Grafik
    col_chart1, col_chart2 = st.columns(2)
    
    with col_chart1:
        st.markdown('<div class="section-title">📈 Flow vs Anomaly (Timeline)</div>', unsafe_allow_html=True)
        chart_data = df.copy()
        chart_data["captured_at"] = pd.to_datetime(chart_data["captured_at"], utc=True)
        chart_data = chart_data.set_index("captured_at")
        
        total_flow_ts = chart_data.resample("1min").size().rename("Total Flow")
        anomaly_ts = chart_data[chart_data["status"].str.lower().str.contains("anomaly", na=False)].resample("1min").size().rename("Total Anomaly")
        
        time_df = pd.concat([total_flow_ts, anomaly_ts], axis=1).fillna(0)
        st.line_chart(time_df, color=["#00f0ff", "#ff4b6e"], height=380)

    with col_chart2:
        st.markdown('<div class="section-title">🗺️ U-Matrix Topology Map</div>', unsafe_allow_html=True)
        if som_model:
            som_chart = create_som_chart(df, som_model)
            if som_chart:
                st.altair_chart(som_chart, use_container_width=True)
        else:
            st.warning("Model SOM tidak ditemukan di path.")

    # Tabel Log
    st.markdown('<div class="section-title">🚨 Recent Anomaly Logs</div>', unsafe_allow_html=True)
    anomaly_logs = df[df["status"].str.lower().str.contains("anomaly", na=False)].head(100)
    if not anomaly_logs.empty:
        st.dataframe(
            anomaly_logs[["captured_at", "src_ip", "dst_ip", "application", "distance", "status"]],
            use_container_width=True, hide_index=True
        )
    else:
        st.success("Jaringan aman. Tidak ada anomali terdeteksi sejauh ini.")
        
    st.caption(f"Last sync: {datetime.now().strftime('%H:%M:%S')} (Auto-refresh 5s)")

def process_offline_csv(df_csv, package):
    st.info("Memproses dataset dengan Model SOM...")
    
    # Isi kolom yang hilang dengan 0
    for col in FEATURE_COLUMNS:
        if col not in df_csv.columns:
            df_csv[col] = 0.0
            
    X_raw = df_csv[FEATURE_COLUMNS].values.astype(float)
    X_log = np.log1p(np.maximum(0.0, X_raw))
    X_clean = np.nan_to_num(X_log, nan=0.0, posinf=1.0, neginf=-1.0)
    
    scaler = package['scaler']
    X_scaled = scaler.transform(X_clean)
    
    som = package['model']
    winner_labels = package['winner_labels']
    
    results = []
    progress_bar = st.progress(0)
    total_rows = len(X_scaled)
    
    update_interval = max(1, (total_rows // 20))
    
    for i, x in enumerate(X_scaled):
        bmu = som.winner(x)
        weights = som.get_weights()[bmu[0], bmu[1]]
        dist = float(np.linalg.norm(x - weights))
        
        if isinstance(winner_labels, dict):
            pred = winner_labels.get(bmu, 0)
        else:
            pred = winner_labels[bmu[0]][bmu[1]]
            
        results.append({
            'som_x': int(bmu[0]),
            'som_y': int(bmu[1]),
            'distance': round(dist, 4),
            'status': 'ANOMALY' if pred == 1 else 'NORMAL'
        })
        
        if i % update_interval == 0:
            progress_bar.progress(min(1.0, i / total_rows))
            
    progress_bar.progress(1.0)
    
    df_results = pd.DataFrame(results)
    df_final = pd.concat([df_csv.reset_index(drop=True), df_results], axis=1)
    return df_final


package = load_som_package()

tab1, tab2 = st.tabs(["🔴 Real-Time Monitoring", "📂 Offline Demo (CSV)"])

with tab1:
    render_realtime_tab(package)

with tab2:
    st.markdown("### Uji Deteksi Zero-Day via File CSV")
    st.write("Unggah file traffic (PCAP yang sudah dikonversi ke CSV / NetFlow) untuk melihat bagaimana model SOM bereaksi terhadap data baru tanpa mengganggu database produksi.")
    
    uploaded_file = st.file_uploader("Unggah File CSV Traffic", type=['csv'])
    
    if uploaded_file is not None:
        if package is None:
            st.error("Gagal menjalankan demo: Paket model SOM tidak ditemukan.")
        else:
            try:
                df_offline = pd.read_csv(uploaded_file)
                st.write(f"Total baris dibaca: **{len(df_offline):,}** baris.")
                
                # Batasi untuk demo agar tidak hang (dinaikkan ke 1 Juta Baris)
                if len(df_offline) > 1000000:
                    st.warning("File terlalu besar untuk demo interaktif. Hanya memproses 1.000.000 baris pertama.")
                    df_offline = df_offline.head(1000000)
                
                if st.button("🚀 Proses Analisis SOM", use_container_width=True):
                    df_result = process_offline_csv(df_offline, package)
                    
                    # Tampilkan Hasil
                    st.markdown("---")
                    tot_off = len(df_result)
                    ano_off = len(df_result[df_result['status'] == 'ANOMALY'])
                    
                    c1, c2 = st.columns(2)
                    c1.metric("Total Paket Dievaluasi", f"{tot_off:,}")
                    c2.metric("Terdeteksi Anomali", f"{ano_off:,}", delta_color="inverse")
                    
                    st.markdown('<div class="section-title">🗺️ U-Matrix Map (Offline Data)</div>', unsafe_allow_html=True)
                    som_chart_off = create_som_chart(df_result, package['model'])
                    if som_chart_off:
                        st.altair_chart(som_chart_off, use_container_width=True)
                        
                    st.markdown('<div class="section-title">📄 Data Hasil Prediksi (Menampilkan Max 1.000 Baris Pertama)</div>', unsafe_allow_html=True)
                    
                    # PERBAIKAN: Gunakan .head(1000) agar Pandas Styler tidak memicu error batas rendering 
                    # dan browser tidak kehabisan memori. Map untuk kompatibilitas versi pandas baru.
                    st.dataframe(
                        df_result.head(1000).style.applymap(
                            lambda x: 'background-color: #4a1924; color: #ffb3c1;' if x == 'ANOMALY' else '', 
                            subset=['status']
                        ),
                        use_container_width=True
                    )
                    
            except Exception as e:
                st.error(f"Terjadi kesalahan saat memproses CSV: {e}")  