from datetime import datetime, timezone

def map_nfstream_to_som_features(flow) -> dict:
    """
    Mengekstrak dan memetakan atribut dari NFStream flow
    menjadi dictionary fitur yang sesuai dengan model GSOM.
    """
    def g(attr, default=0):
        val = getattr(flow, attr, default)
        return val if val is not None else default

    captured_ttl = getattr(flow.udps, "ttl", 0)

    d_ms = g("bidirectional_duration_ms")
    # Hindari division by zero: minimal 1ms
    d_sec = max(d_ms, 1) / 1000.0

    # Konstruksi TCP flags manual (lebih reliable di Windows)
    tcp_flags = 0
    if g("bidirectional_syn_packets") > 0: tcp_flags |= 0x02
    if g("bidirectional_ack_packets") > 0: tcp_flags |= 0x10
    if g("bidirectional_psh_packets") > 0: tcp_flags |= 0x08
    if g("bidirectional_rst_packets") > 0: tcp_flags |= 0x04
    if g("bidirectional_fin_packets") > 0: tcp_flags |= 0x01

    # Fallback ke attribute bawaan jika akumulator manual gagal
    if tcp_flags == 0:
        tcp_flags = g("bidirectional_tcp_flags", 0)

    return {
        "source": "live_capture_nfstream",
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "src_ip": g("src_ip"),
        "dst_ip": g("dst_ip"),
        "application_name": g("application_name", "Unknown"),
        "PROTOCOL": g("protocol"),
        "L7_PROTO": g("application_id", g("application_category_id")),
        "IN_BYTES": g("src2dst_bytes"),
        "IN_PKTS": g("src2dst_packets"),
        "OUT_BYTES": g("dst2src_bytes"),
        "OUT_PKTS": g("dst2src_packets"),
        "TCP_FLAGS": tcp_flags,
        "CLIENT_TCP_FLAGS": g("src2dst_tcp_flags"),
        "SERVER_TCP_FLAGS": g("dst2src_tcp_flags"),
        "FLOW_DURATION_MILLISECONDS": d_ms,
        "DURATION_IN": g("src2dst_duration_ms"),
        "DURATION_OUT": g("dst2src_duration_ms"),
        "MIN_TTL": captured_ttl if captured_ttl > 0 else g("bidirectional_min_ttl"),
        "MAX_TTL": captured_ttl if captured_ttl > 0 else g("bidirectional_max_ttl"),
        "LONGEST_FLOW_PKT": g("bidirectional_max_ps"),
        "SHORTEST_FLOW_PKT": g("bidirectional_min_ps"),
        "MIN_IP_PKT_LEN": g("bidirectional_min_ps"),
        "MAX_IP_PKT_LEN": g("bidirectional_max_ps"),
        "SRC_TO_DST_AVG_THROUGHPUT": (g("src2dst_bytes") * 8) / d_sec,
        "DST_TO_SRC_AVG_THROUGHPUT": (g("dst2src_bytes") * 8) / d_sec,
        "TCP_WIN_MAX_IN": g("src2dst_max_window_size"),
        "TCP_WIN_MAX_OUT": g("dst2src_max_window_size"),
        "Label": 0,
    }