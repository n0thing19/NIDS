import streamlit as st
import psycopg2
import pandas as pd
from datetime import datetime

st.set_page_config(page_title="NIDS Dashboard", layout="wide")

# --- STYLE CSS ---
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap');
    html, body, [class*="css"] { font-family: 'Rajdhani', sans-serif; }
    .stApp { background-color: #0a0e1a; color: #e0e6f0; }
    h1, h2, h3 { font-family: 'Share Tech Mono', monospace !important; color: #00f0ff !important; }
    .metric-card { background: linear-gradient(135deg, #0d1b2a, #112240); border: 1px solid #00f0ff33; border-radius: 12px; padding: 1.5rem 2rem; text-align: center; }
    .metric-label { font-family: 'Share Tech Mono', monospace; font-size: 0.85rem; color: #7a9fc0; text-transform: uppercase; }
    .metric-value { font-family: 'Share Tech Mono', monospace; font-size: 3rem; font-weight: bold; }
    .metric-flow { color: #00f0ff; }
    .metric-anomaly { color: #ff4b6e; }
    .section-title { font-family: 'Share Tech Mono', monospace; color: #00f0ff; border-left: 3px solid #00f0ff; padding-left: 0.75rem; margin: 2rem 0 1rem 0; }
</style>
""", unsafe_allow_html=True)

st.markdown("# NIDS — Network Intrusion Detection")
st.markdown("---")

# Cache data diturunkan TTL-nya agar sinkron dengan refresh rate
@st.cache_data(ttl=2)
def load_data():
    try:
        conn = psycopg2.connect(
            host="localhost", port=5432,
            dbname="nids", user="postgres", password="postgres"
        )
        query = """
            SELECT id, captured_at, status, src_ip, dst_ip, accuracy_percent, som_x, som_y 
            FROM nids_alerts 
            ORDER BY captured_at DESC
        """
        df = pd.read_sql(query, conn)
        conn.close()
        return df
    except Exception as e:
        st.error(f"Detail Error Database: {e}")
        return None

# --- BAGIAN REAL-TIME (FRAGMENT) ---
# Fungsi ini akan dijalankan ulang setiap 5 detik tanpa refresh seluruh halaman
@st.fragment(run_every=5)
def render_dashboard():
    df = load_data()
    
    if df is None or df.empty:
        st.warning("Menunggu data...")
        return

    # --- METRIK ---
    total_flow = len(df)
    total_anomaly = df["status"].str.lower().str.contains("anomaly", na=False).sum()

    col1, col2 = st.columns(2)
    with col1:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">Total Flow</div>
            <div class="metric-value metric-flow">{total_flow:,}</div>
        </div>
        """, unsafe_allow_html=True)
    with col2:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-label">Total Anomaly</div>
            <div class="metric-value metric-anomaly">{total_anomaly:,}</div>
        </div>
        """, unsafe_allow_html=True)

    # --- BAGIAN GRAFIK ---
    st.markdown('<div class="section-title">Grafik Traffic — Flow vs Anomaly</div>', unsafe_allow_html=True)
    
    chart_data = df.copy()
    chart_data["captured_at"] = pd.to_datetime(chart_data["captured_at"], utc=True)
    chart_data = chart_data.set_index("captured_at")
    
    total_flow_ts = chart_data.resample("1min").size().rename("Total Flow")
    anomaly_ts = (
        chart_data[chart_data["status"].str.lower().str.contains("anomaly", na=False)]
        .resample("1min").size().rename("Total Anomaly")
    )
    chart_df = pd.concat([total_flow_ts, anomaly_ts], axis=1).fillna(0)
    st.line_chart(chart_df, color=["#00f0ff", "#ff4b6e"], height=350)

    # --- BAGIAN MAP SOM ---
    st.markdown('<div class="section-title">SOM Topology Map — Cluster Visualization</div>', unsafe_allow_html=True)
        
    if "som_x" in df.columns and "som_y" in df.columns:
        # Pisahkan data normal dan anomali untuk warna berbeda
        map_df = df.copy()
        map_df['color'] = map_df['status'].apply(lambda x: '#ff4b6e' if 'anomaly' in x.lower() else '#00f0ff')
            
        # Plot menggunakan scatter chart
        st.scatter_chart(
            map_df,
            x='som_x',
            y='som_y',
            color='color',
            size=70,
            height=400,
            use_container_width=True
        )
        st.caption("🔴 Merah: Anomali | 🔵 Biru: Normal (Posisi berdasarkan koordinat neuron SOM)")
    else:
        st.info("Kolom koordinat SOM (som_x, som_y) tidak ditemukan di database.")

    # --- BAGIAN TABEL LOG ---
    st.markdown('<div class="section-title">Log Anomaly Terdeteksi</div>', unsafe_allow_html=True)
    anomaly_logs = df[df["status"].str.lower().str.contains("anomaly", na=False)].copy()

    if not anomaly_logs.empty:
        display_df = anomaly_logs[["captured_at", "src_ip", "dst_ip", "accuracy_percent", "status"]].copy()
        
        st.dataframe(
            display_df,
            use_container_width=True,
            hide_index=True,
            column_config={
                "captured_at": "Timestamp",
                "src_ip": "Source IP",
                "dst_ip": "Destination IP",
                "accuracy_percent": "Accuracy (%)",
                "status": "Detection"
            }
        )
    else:
        st.info("Tidak ada log anomali saat ini.")
    
    # Penanda update terakhir
    st.caption(f"Terakhir diperbarui: {datetime.now().strftime('%H:%M:%S')} (Auto-refresh setiap 5 detik)")

# Panggil fungsi fragment untuk menampilkan konten
render_dashboard()

