import streamlit as st
import psycopg2
import pandas as pd

st.set_page_config(page_title="NIDS Dashboard", layout="wide")

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

@st.cache_data(ttl=5)
def load_data():
    conn = psycopg2.connect(
        host="localhost", port=5432,
        dbname="nids", user="postgres", password="postgres"
    )
    df = pd.read_sql(
        "SELECT id, captured_at, status FROM nids_alerts ORDER BY captured_at ASC",
        conn
    )
    conn.close()
    return df

try:
    df = load_data()
except Exception as e:
    st.error(f"Gagal koneksi ke database: {e}")
    st.stop()

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

st.markdown('<div class="section-title">Grafik Traffic — Flow vs Anomaly</div>', unsafe_allow_html=True)

if "captured_at" in df.columns and not df.empty:
    df["captured_at"] = pd.to_datetime(df["captured_at"], utc=True)
    df = df.set_index("captured_at")
    total_flow_ts = df.resample("1min").size().rename("Total Flow")
    anomaly_ts = (
        df[df["status"].str.lower().str.contains("anomaly", na=False)]
        .resample("1min").size().rename("Total Anomaly")
    )
    chart_df = pd.concat([total_flow_ts, anomaly_ts], axis=1).fillna(0)
    st.line_chart(chart_df, color=["#00f0ff", "#ff4b6e"], height=350)
else:
    st.warning("Tidak ada data untuk ditampilkan.")

st.markdown("---")
st.caption("Data auto-refresh setiap 5 detik - NIDS AI Engine (SOM)")

if st.button("Refresh Manual"):
    st.cache_data.clear()
    st.rerun()