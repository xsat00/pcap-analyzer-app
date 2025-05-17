import streamlit as st
from scapy.all import *
import pandas as pd
import plotly.express as px
from collections import Counter
import tempfile

# At the top of your app.py
import streamlit as st

# Dummy credentials
USER = "admin"
PASS = "007"

# Login check
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False

if not st.session_state.authenticated:
    st.title("🔐 Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        if username == USER and password == PASS:
            st.session_state.authenticated = True
            st.experimental_rerun()
        else:
            st.error("Invalid credentials")
    st.stop()

st.set_page_config(page_title="🔍 Advanced PCAP Analyzer", layout="wide")
st.title("📡 Advanced PCAP Network Traffic Analyzer")

@st.cache_data(show_spinner=False)
def parse_pcap(file_path):
    packets = rdpcap(file_path)

    protocol_counter = Counter()
    ip_traffic_counter = Counter()
    details = []

    for pkt in packets:
        proto = "Other"
        src = pkt[IP].src if IP in pkt else "N/A"
        dst = pkt[IP].dst if IP in pkt else "N/A"
        size = len(pkt)

        # Protocol Detection by Layer
        if pkt.haslayer(TCP):
            if pkt.haslayer(Raw) and b"HTTP" in bytes(pkt[Raw]):
                proto = "HTTP"
            else:
                proto = "TCP"
        elif pkt.haslayer(UDP):
            if pkt.haslayer(DNS):
                proto = "DNS"
            else:
                proto = "UDP"
        elif pkt.haslayer(ICMP):
            proto = "ICMP"
        elif pkt.haslayer(ARP):
            proto = "ARP"
            src = pkt[ARP].psrc
            dst = pkt[ARP].pdst

        protocol_counter[proto] += 1
        if src != "N/A":
            ip_traffic_counter[src] += size
        if dst != "N/A":
            ip_traffic_counter[dst] += size

        details.append({
            'Source': src,
            'Destination': dst,
            'Protocol': proto,
            'Size': size
        })

    df_details = pd.DataFrame(details)
    return protocol_counter, ip_traffic_counter, df_details

def plot_protocol_chart(protocol_data):
    df = pd.DataFrame(protocol_data.items(), columns=["Protocol", "Count"])
    fig = px.pie(df, names='Protocol', values='Count', title='Traffic by Protocol')
    return fig

def plot_top_ips(ip_data, top_n=10):
    top_ips = dict(Counter(ip_data).most_common(top_n))
    df = pd.DataFrame(top_ips.items(), columns=["IP", "Traffic Volume (bytes)"])
    fig = px.bar(df, x="IP", y="Traffic Volume (bytes)", title="Top IPs by Traffic Volume")
    return fig

uploaded_file = st.file_uploader("📁 Upload a PCAP file to analyze", type=["pcap","pcapng"])

if uploaded_file:
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(uploaded_file.read())
        tmp_path = tmp.name

    try:
        protocol_data, ip_data, full_df = parse_pcap(tmp_path)

        st.success(f"📦 Parsed {len(full_df)} packets.")
        st.subheader("📊 Protocol Distribution")
        st.plotly_chart(plot_protocol_chart(protocol_data), use_container_width=True)

        st.subheader("🏆 Top Talkers (IP Addresses by Traffic)")
        st.plotly_chart(plot_top_ips(ip_data), use_container_width=True)

        st.subheader("🔎 Filter and Explore Packets")

        with st.sidebar:
            st.header("⚙️ Filter by Protocol")
            proto_filter = st.multiselect(
                "Protocols", full_df['Protocol'].unique(), default=full_df['Protocol'].unique()
            )

        filtered_df = full_df[full_df['Protocol'].isin(proto_filter)]
        st.dataframe(filtered_df.sort_values(by="Size", ascending=False), use_container_width=True)

        st.markdown("---")
        st.caption("Developed by Xsat for DRDO | Protocols: TCP, UDP, ICMP, ARP, DNS, HTTP")

        st.subheader("📥 Download Packet Report")
        csv = filtered_df.to_csv(index=False).encode("utf-8")
        st.download_button(
            label="Download as CSV",
            data=csv,
            file_name="pcap_analysis.csv",
            mime="text/csv"
        )

    except Exception as e:
        st.error(f"❌ Failed to parse PCAP file: {e}")
