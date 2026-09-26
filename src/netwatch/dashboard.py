import streamlit as st
from netwatch.analyzer import (
    get_traffic_summary, get_protocol_stats, 
    get_top_source_hosts, get_top_sources_by_bytes,
    get_network_flows
)

from netwatch.detector import (
    detect_port_scan,
    detect_host_sweep,
    detect_high_volume_flow,
    detect_excessive_syn,
)

from netwatch.alerts import generate_alerts


st.title("NetWatch")
st.write("Network traffic observability and behavioral detection dashboard.")

total_packets, total_bytes, unique_sources, unique_destinations = get_traffic_summary()
total_mb = total_bytes / 1024 / 1024

col1, col2, col3, col4 = st.columns(4)


col1.metric("Total Packets", total_packets)
col2.metric("Total Bytes", f"{total_mb:.2f} MB")
col3.metric("Unique Sources", unique_sources)
col4.metric("Unique Destinations", unique_destinations)

st.subheader("Protocol Distribution")

protocol_stats = get_protocol_stats()
protocol_data = {}


for protocol, packet_count in protocol_stats:
    protocol_data[protocol] = packet_count
    
st.bar_chart(protocol_data)

st.subheader("Top Source Hosts")
top_sources = get_top_source_hosts(5)

source_data = {}

for source_ip, packet_count in top_sources:
    source_data[source_ip] = packet_count

st.bar_chart(source_data)

st.subheader("Top Sources by Traffic Volume")
top_sources_by_bytes = get_top_sources_by_bytes(5)
source_bytes_data = {}

for source_ip, total_bytes in top_sources_by_bytes:
    source_mb = total_bytes / 1024 / 1024
    source_bytes_data[source_ip] = source_mb

st.bar_chart(source_bytes_data)


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
    "Bytes": flow[6],
    "Duration": round(flow[9], 2),
}
    flow_data.append(flow_row)
st.dataframe(flow_data)


st.subheader("Security Alerts")

port_scan_results = detect_port_scan(10)


host_sweep_results = detect_host_sweep(10)


high_volume_results = detect_high_volume_flow(1_000_000)


excessive_syn_results = detect_excessive_syn(50)

alerts = generate_alerts(
    port_scan_results,
    host_sweep_results,
    high_volume_results,
    excessive_syn_results,
)

if not alerts:
    st.success("No security alerts detected.")
else:
    for alert in alerts:
        alert_title = alert["type"].replace("_", " ").title()
        message = f"{alert_title} — {alert['severity'].upper()}\n{alert['explanation']}"
        if alert["severity"] == "high":
            st.error(message)
        elif alert["severity"] == "medium":
            st.warning(message)
        else:
            st.info(message)
