import streamlit as st

from netwatch.analyzer import (
    get_traffic_summary,
    get_protocol_stats,
    get_top_source_hosts,
    get_top_sources_by_bytes,
    get_network_flows,
)

from netwatch.detector import (
    detect_port_scan,
    detect_host_sweep,
    detect_high_volume_flow,
    detect_excessive_syn,
)

from netwatch.alerts import generate_alerts


# ---------------------------------------------------------
# Page configuration
# ---------------------------------------------------------

st.set_page_config(
    page_title="NetWatch",
    layout="wide",
)


# ---------------------------------------------------------
# Header
# ---------------------------------------------------------

st.title("NetWatch")
st.caption("Network traffic observability and behavioral anomaly detection")

st.write(
    "Analyze captured network traffic, inspect communication patterns, "
    "and identify potentially unusual network behavior."
)

st.divider()


# ---------------------------------------------------------
# Sidebar — Detection Settings
# ---------------------------------------------------------

st.sidebar.header("Detection Settings")

st.sidebar.caption(
    "Configure behavioral detection thresholds for the current capture."
)

port_scan_threshold = st.sidebar.number_input(
    "Port Scan Threshold",
    min_value=1,
    value=10,
    step=1,
    help=(
        "Unique TCP destination ports contacted by one source "
        "before an alert is generated."
    ),
)

host_sweep_threshold = st.sidebar.number_input(
    "Host Sweep Threshold",
    min_value=1,
    value=10,
    step=1,
    help=(
        "Unique destination hosts contacted by one source "
        "before an alert is generated."
    ),
)

high_volume_threshold_mb = st.sidebar.number_input(
    "High Volume Threshold (MB)",
    min_value=0.1,
    value=1.0,
    step=0.1,
    help=(
        "Traffic volume required for a network flow "
        "to generate an alert."
    ),
)

excessive_syn_threshold = st.sidebar.number_input(
    "Excessive SYN Threshold",
    min_value=1,
    value=50,
    step=1,
    help=(
        "Number of TCP SYN packets required within the configured "
        "time window before an alert is generated."
    ),
)

syn_window_seconds = st.sidebar.number_input(
    "SYN Detection Window (seconds)",
    min_value=1,
    value=10,
    step=1,
    help=(
        "Time window used to identify bursts of TCP SYN activity."
    ),
)

high_volume_threshold_bytes = (
    high_volume_threshold_mb * 1024 * 1024
)


# ---------------------------------------------------------
# Traffic Overview
# ---------------------------------------------------------

st.header("Traffic Overview")

total_packets, total_bytes, unique_sources, unique_destinations = (
    get_traffic_summary()
)

total_mb = total_bytes / 1024 / 1024

col1, col2, col3, col4 = st.columns(4)

col1.metric(
    "Total Packets",
    f"{total_packets:,}",
)

col2.metric(
    "Total Traffic",
    f"{total_mb:.2f} MB",
)

col3.metric(
    "Unique Sources",
    f"{unique_sources:,}",
)

col4.metric(
    "Unique Destinations",
    f"{unique_destinations:,}",
)


# ---------------------------------------------------------
# Protocol Distribution
# ---------------------------------------------------------

st.subheader("Protocol Distribution")

protocol_stats = get_protocol_stats()
protocol_data = {}

for protocol, packet_count in protocol_stats:
    protocol_data[protocol] = packet_count

st.bar_chart(protocol_data)


# ---------------------------------------------------------
# Top Source Hosts
# ---------------------------------------------------------

st.subheader("Top Source Hosts")

top_sources = get_top_source_hosts(5)
source_data = {}

for source_ip, packet_count in top_sources:
    source_data[source_ip] = packet_count

st.bar_chart(source_data)


# ---------------------------------------------------------
# Top Sources by Traffic Volume
# ---------------------------------------------------------

st.subheader("Top Sources by Traffic Volume")

top_sources_by_bytes = get_top_sources_by_bytes(5)
source_bytes_data = {}

for source_ip, source_total_bytes in top_sources_by_bytes:
    source_mb = source_total_bytes / 1024 / 1024
    source_bytes_data[source_ip] = source_mb

st.bar_chart(source_bytes_data)


# ---------------------------------------------------------
# Top Network Flows
# ---------------------------------------------------------

st.subheader("Top Network Flows")

network_flows = get_network_flows(10)
flow_data = []

for flow in network_flows:
    flow_row = {
        "Source": flow[0],
        "Destination": flow[1],
        "Source Port": flow[2],
        "Destination Port": flow[3],
        "Protocol": flow[4],
        "Packets": flow[5],
        "Traffic (MB)": round(flow[6] / 1024 / 1024, 2),
        "Duration (s)": round(flow[9], 2),
    }

    flow_data.append(flow_row)

st.dataframe(
    flow_data,
    use_container_width=True,
    hide_index=True,
)


# ---------------------------------------------------------
# Security Analysis
# ---------------------------------------------------------

st.divider()

st.header("Security Analysis")

st.caption(
    "Behavioral detections based on the configured thresholds."
)

port_scan_results = detect_port_scan(
    port_scan_threshold
)

host_sweep_results = detect_host_sweep(
    host_sweep_threshold
)

high_volume_results = detect_high_volume_flow(
    high_volume_threshold_bytes
)

excessive_syn_results = detect_excessive_syn(
    excessive_syn_threshold,
    syn_window_seconds,
)

alerts = generate_alerts(
    port_scan_results,
    host_sweep_results,
    high_volume_results,
    excessive_syn_results,
)


# ---------------------------------------------------------
# Alert Summary
# ---------------------------------------------------------

st.metric(
    "Active Alerts",
    len(alerts),
)


# ---------------------------------------------------------
# Alert Details
# ---------------------------------------------------------

if not alerts:
    st.success("No security alerts detected.")

else:
    for alert in alerts:
        alert_title = (
            alert["type"]
            .replace("_", " ")
            .title()
        )

        message = (
            f"**{alert_title} — {alert['severity'].upper()}**\n\n"
            f"{alert['explanation']}"
        )

        if alert["severity"] == "high":
            st.error(message)

        elif alert["severity"] == "medium":
            st.warning(message)

        else:
            st.info(message)