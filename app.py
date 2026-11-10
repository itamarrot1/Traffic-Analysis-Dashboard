# =============================================================================
# PCAP Dashboard - Network Traffic Analysis Dashboard
# =============================================================================
# This tool receives a PCAP or PCAPNG file and displays detailed information:
# 1. General capture info (packet count, times, protocols)
# 2. HTTP transaction recovery (requests & responses)
# 3. AI-powered questions about the captured data
# =============================================================================

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from scapy.all import (
    rdpcap,       # Function to read PCAP/PCAPNG files
    IP,           # IP layer - source and destination addresses
    TCP,          # TCP layer - ports and flags
    UDP,          # UDP layer
    DNS,          # DNS layer
    Raw,          # Raw payload data
)
from scapy.layers.http import (
    HTTPRequest,  # HTTP request (GET, POST, etc.)
    HTTPResponse, # HTTP response (200 OK, 404, etc.)
)
from datetime import datetime
import tempfile
import os
import json
import re

# ──────────────────────────────────────────────────────────────────────────────
# Page Configuration
# ──────────────────────────────────────────────────────────────────────────────
# page_config must be the first Streamlit command
st.set_page_config(
    page_title="PCAP Dashboard",  # Browser tab title
    page_icon="🔍",               # Browser tab icon
    layout="wide"                  # Wide layout - uses the full screen width
)

# Main dashboard title
st.title("🔍 PCAP/PCAPNG Dashboard")
st.markdown("**A tool for analyzing network traffic from PCAP files**")
st.markdown("---")


# =============================================================================
# Helper Functions
# =============================================================================

def get_protocol_name(packet):
    """
    Identifies the highest-level protocol in a packet.
    
    Every network packet is built like layers of an onion: Ethernet > IP > TCP > HTTP.
    This function traverses all layers and returns the name of the highest one,
    because that's the most interesting layer (e.g., HTTP rather than TCP).
    
    Args:
        packet: A Scapy packet object
    Returns:
        Protocol name as a string
    """
    # Specific check for HTTP since Scapy doesn't always auto-detect it
    if packet.haslayer(HTTPRequest) or packet.haslayer(HTTPResponse):
        return "HTTP"
    
    # Check for DNS
    if packet.haslayer(DNS):
        return "DNS"
    
    # Traverse all layers from highest to lowest
    # lastlayer() returns the topmost layer
    layer = packet
    protocol = "Unknown"
    while layer:
        name = layer.__class__.__name__
        # Skip "technical" layers that aren't relevant to us
        if name not in ["Raw", "Padding", "Ether", "Dot1Q"]:
            protocol = name
        layer = layer.payload if layer.payload and not isinstance(layer.payload, bytes) else None
    return protocol


def extract_http_transactions(packets):
    """
    Extracts HTTP transactions - matches each request to its response.
    
    Logic: An HTTP request and response sent over the same TCP stream
    (same IP:Port pair) belong to the same transaction.
    
    We use the TCP stream as the key:
    - Request:  (src_ip, src_port, dst_ip, dst_port)
    - Response: (dst_ip, dst_port, src_ip, src_port) - the reverse of the request
    
    Args:
        packets: List of Scapy packets
    Returns:
        List of dictionaries, each representing a complete HTTP transaction
    """
    transactions = []
    
    # Dictionary to store requests waiting for their matching response
    # The key is the stream identifier (pair of addresses and ports)
    pending_requests = {}
    
    for i, pkt in enumerate(packets):
        frame_number = i + 1  # Frame numbers start from 1 (like in Wireshark)
        
        if pkt.haslayer(HTTPRequest):
            # ──── Found an HTTP Request ────
            http_req = pkt[HTTPRequest]
            
            # Extract request fields
            # decode('utf-8', errors='ignore') converts bytes to string
            method = http_req.Method.decode('utf-8', errors='ignore') if http_req.Method else "N/A"
            
            # The URI is the requested path (e.g., /index.html)
            uri = http_req.Path.decode('utf-8', errors='ignore') if http_req.Path else "N/A"
            
            # Host - the server name (e.g., www.example.com)
            host = http_req.Host.decode('utf-8', errors='ignore') if http_req.Host else "N/A"
            
            # Source and destination IP addresses
            src_ip = pkt[IP].src if pkt.haslayer(IP) else "N/A"
            dst_ip = pkt[IP].dst if pkt.haslayer(IP) else "N/A"
            
            # Source and destination ports
            src_port = pkt[TCP].sport if pkt.haslayer(TCP) else 0
            dst_port = pkt[TCP].dport if pkt.haslayer(TCP) else 0
            
            # Request timestamp - when the packet was captured
            req_time = float(pkt.time)
            
            # Create a unique key to identify the stream
            # The request goes from client to server
            stream_key = (src_ip, src_port, dst_ip, dst_port)
            
            # Store the request in the dictionary, waiting for its response
            pending_requests[stream_key] = {
                "method": method,
                "uri": uri,
                "host": host,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "req_time": req_time,
                "req_frame": frame_number,
            }
        
        elif pkt.haslayer(HTTPResponse):
            # ──── Found an HTTP Response ────
            http_resp = pkt[HTTPResponse]
            
            # Addresses - note: in the response, the server is the source
            src_ip = pkt[IP].src if pkt.haslayer(IP) else "N/A"
            dst_ip = pkt[IP].dst if pkt.haslayer(IP) else "N/A"
            src_port = pkt[TCP].sport if pkt.haslayer(TCP) else 0
            dst_port = pkt[TCP].dport if pkt.haslayer(TCP) else 0
            
            # The stream key is reversed - because the response goes from server to client
            # If the request was (client -> server), the response is (server -> client)
            stream_key = (dst_ip, dst_port, src_ip, src_port)
            
            # Status Code - the response code (200, 404, 500, etc.)
            status_code = http_resp.Status_Code.decode('utf-8', errors='ignore') if http_resp.Status_Code else "N/A"
            
            # Response timestamp
            resp_time = float(pkt.time)
            
            # Look for the matching request
            if stream_key in pending_requests:
                req_info = pending_requests.pop(stream_key)
                
                # Calculate response time - the difference between sending the request and receiving the response
                response_time_ms = (resp_time - req_info["req_time"]) * 1000  # milliseconds
                
                # Create a complete transaction record
                transactions.append({
                    "method": req_info["method"],
                    "uri": req_info["uri"],
                    "host": req_info["host"],
                    "src_ip": req_info["src_ip"],      # Client address
                    "dst_ip": req_info["dst_ip"],      # Server address
                    "src_port": req_info["src_port"],
                    "dst_port": req_info["dst_port"],
                    "status_code": status_code,
                    "response_time_ms": round(response_time_ms, 2),
                    "req_frame": req_info["req_frame"],   # Request frame number
                    "resp_frame": frame_number,            # Response frame number
                    "req_timestamp": req_info["req_time"],
                    "resp_timestamp": resp_time,
                })
    
    # Requests with no matching response - still add them (without response data)
    for stream_key, req_info in pending_requests.items():
        transactions.append({
            "method": req_info["method"],
            "uri": req_info["uri"],
            "host": req_info["host"],
            "src_ip": req_info["src_ip"],
            "dst_ip": req_info["dst_ip"],
            "src_port": req_info["src_port"],
            "dst_port": req_info["dst_port"],
            "status_code": "No Response",
            "response_time_ms": None,
            "req_frame": req_info["req_frame"],
            "resp_frame": None,
            "req_timestamp": req_info["req_time"],
            "resp_timestamp": None,
        })
    
    return transactions


def build_packet_summary(packets):
    """
    Builds a detailed summary of all packets for AI questions.
    
    This function creates a text string containing all the important information
    about the capture, so we can send it to the AI as context.
    
    Args:
        packets: List of Scapy packets
    Returns:
        A string with a detailed summary
    """
    summary_lines = []
    summary_lines.append(f"=== PCAP Capture Summary ===")
    summary_lines.append(f"Total packets: {len(packets)}")
    
    if len(packets) > 0:
        # Start and end times
        start_time = float(packets[0].time)
        end_time = float(packets[-1].time)
        duration = end_time - start_time
        summary_lines.append(f"Start time: {datetime.fromtimestamp(start_time)}")
        summary_lines.append(f"End time: {datetime.fromtimestamp(end_time)}")
        summary_lines.append(f"Duration: {duration:.3f} seconds")
    
    # Protocol counts
    protocol_counts = {}
    for pkt in packets:
        proto = get_protocol_name(pkt)
        protocol_counts[proto] = protocol_counts.get(proto, 0) + 1
    
    summary_lines.append(f"\n=== Protocol Distribution ===")
    for proto, count in sorted(protocol_counts.items(), key=lambda x: -x[1]):
        summary_lines.append(f"{proto}: {count} packets")
    
    # Top endpoint IP addresses (so the AI can answer questions about them)
    ip_counts = {}
    for pkt in packets:
        if pkt.haslayer(IP):
            src = pkt[IP].src
            dst = pkt[IP].dst
            ip_counts[src] = ip_counts.get(src, 0) + 1
            ip_counts[dst] = ip_counts.get(dst, 0) + 1
    
    summary_lines.append(f"\n=== Top Endpoint IP Addresses ===")
    for ip, count in sorted(ip_counts.items(), key=lambda x: -x[1])[:15]:
        summary_lines.append(f"{ip}: {count} packets")
    
    # Packet details (up to 500 packets to avoid exceeding token limits)
    summary_lines.append(f"\n=== Packet Details (first 500) ===")
    for i, pkt in enumerate(packets[:500]):
        frame = i + 1
        timestamp = float(pkt.time)
        time_str = datetime.fromtimestamp(timestamp).strftime("%H:%M:%S.%f")
        proto = get_protocol_name(pkt)
        
        src_ip = pkt[IP].src if pkt.haslayer(IP) else "N/A"
        dst_ip = pkt[IP].dst if pkt.haslayer(IP) else "N/A"
        
        line = f"Frame {frame} | {time_str} | {proto} | {src_ip} -> {dst_ip}"
        
        # Add extra details based on protocol type
        if pkt.haslayer(TCP):
            line += f" | TCP {pkt[TCP].sport}->{pkt[TCP].dport}"
            # TCP Flags - indicate the type of packet (SYN, ACK, FIN, etc.)
            flags = pkt[TCP].flags
            line += f" [{flags}]"
        
        if pkt.haslayer(HTTPRequest):
            req = pkt[HTTPRequest]
            method = req.Method.decode('utf-8', errors='ignore') if req.Method else ""
            path = req.Path.decode('utf-8', errors='ignore') if req.Path else ""
            host = req.Host.decode('utf-8', errors='ignore') if req.Host else ""
            line += f" | HTTP Request: {method} {host}{path}"
        
        if pkt.haslayer(HTTPResponse):
            resp = pkt[HTTPResponse]
            status = resp.Status_Code.decode('utf-8', errors='ignore') if resp.Status_Code else ""
            reason = resp.Reason_Phrase.decode('utf-8', errors='ignore') if resp.Reason_Phrase else ""
            line += f" | HTTP Response: {status} {reason}"
        
        if pkt.haslayer(DNS):
            dns = pkt[DNS]
            if dns.qr == 0:  # Query
                if dns.qdcount > 0 and dns.qd:
                    qname = dns.qd.qname.decode('utf-8', errors='ignore') if dns.qd.qname else ""
                    line += f" | DNS Query: {qname}"
            else:  # Response
                line += f" | DNS Response"
        
        summary_lines.append(line)
    
    return "\n".join(summary_lines)


def ask_ai(question, context, api_key):
    """
    Sends a question to Gemini AI with the capture data as context.
    
    The AI receives all the information about the capture (context) and answers
    questions based on the actual data. It must always cite evidence!
    
    Args:
        question: The user's question
        context: Capture summary (from build_packet_summary)
        api_key: Gemini API key
    Returns:
        The AI's answer as a string
    """
    try:
        import google.generativeai as genai
        
        # Configure the API key
        genai.configure(api_key=api_key)
        
        # Create the model
        model = genai.GenerativeModel('gemini-2.0-flash')
        
        # The prompt - instructions for the AI on how to answer
        prompt = f"""You are a network traffic analysis expert. 
You are analyzing a PCAP capture file. Below is a detailed summary of the captured packets.

IMPORTANT RULES:
1. Answer ONLY based on the data provided below. Do not make up information.
2. Always provide evidence for your answers - cite specific frame numbers, timestamps, IP addresses, or other concrete data.
3. If you cannot find the answer in the data, say so explicitly.
4. Answer in the same language as the question.
5. Format your evidence clearly, for example: "Evidence: Frame #42, timestamp 10:23:45.123"

=== CAPTURE DATA ===
{context}
=== END OF DATA ===

User Question: {question}

Please provide a detailed answer with evidence from the capture data."""

        # Send the question to the AI
        response = model.generate_content(prompt)
        return response.text
    
    except Exception as e:
        return f"Error connecting to AI: {str(e)}"


# =============================================================================
# Part 1: Loading the Capture (Sections 23-26)
# =============================================================================
st.header("📂 Load Capture File")
st.markdown("""
> Upload a **PCAP** or **PCAPNG** file to begin analysis.
> The tool will display general info, protocols, and charts.
""")

# ── Section 23: Allow choosing a PCAP or PCAPNG file ──
# file_uploader creates a file upload button
# type restricts which file types are allowed
uploaded_file = st.file_uploader(
    "Choose a PCAP/PCAPNG file",
    type=["pcap", "pcapng"],
    help="Drag and drop a file here or click to browse"
)

# Check if a file was uploaded
if uploaded_file is not None:
    # Save the file temporarily so Scapy can read it
    # (Scapy needs a file path, not raw bytes)
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
        tmp.write(uploaded_file.getvalue())
        tmp_path = tmp.name
    
    # Read the file with Scapy
    # rdpcap = Read PCAP - reads all packets from the file
    # st.spinner displays a loading animation while the file is being read
    with st.spinner("⏳ Reading file..."):
        packets = rdpcap(tmp_path)
    
    # Delete the temporary file - we no longer need it
    os.unlink(tmp_path)
    
    # ── Success message ──
    st.success(f"✅ File loaded successfully! Found **{len(packets)}** packets.")
    
    # ══════════════════════════════════════════════════════════════════════
    # Section 24: Packet count, start time, end time, and capture duration
    # ══════════════════════════════════════════════════════════════════════
    st.subheader("📊 General Capture Information")
    
    if len(packets) > 0:
        # pkt.time - the timestamp of each packet (seconds since 1970, "Unix time")
        start_time = datetime.fromtimestamp(float(packets[0].time))
        end_time = datetime.fromtimestamp(float(packets[-1].time))
        duration_seconds = float(packets[-1].time) - float(packets[0].time)
        
        # Display in 4 side-by-side columns
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            # st.metric - displays a large number with a label
            st.metric("📦 Packet Count", f"{len(packets):,}")
        with col2:
            st.metric("🕐 Start Time", start_time.strftime("%H:%M:%S"))
        with col3:
            st.metric("🕐 End Time", end_time.strftime("%H:%M:%S"))
        with col4:
            st.metric("⏱️ Duration", f"{duration_seconds:.2f} sec")
        
        # Display full dates
        st.caption(f"📅 Start date: {start_time.strftime('%Y-%m-%d %H:%M:%S.%f')}")
        st.caption(f"📅 End date: {end_time.strftime('%Y-%m-%d %H:%M:%S.%f')}")
    
    st.markdown("---")
    
    # ══════════════════════════════════════════════════════════════════════
    # Section 25: Main endpoint addresses AND main protocols found
    # ══════════════════════════════════════════════════════════════════════
    st.subheader("🌐 Endpoint Addresses & Protocol Summary")
    
    # ── Top Endpoint IP Addresses ──
    # Count how many packets each IP address appears in (as source OR destination)
    # An "endpoint" is any device that sent or received traffic in the capture
    ip_counts = {}
    for pkt in packets:
        if pkt.haslayer(IP):
            src = pkt[IP].src
            dst = pkt[IP].dst
            ip_counts[src] = ip_counts.get(src, 0) + 1
            ip_counts[dst] = ip_counts.get(dst, 0) + 1
    
    if ip_counts:
        # Sort by packet count (highest first) and take the top 10
        sorted_ips = sorted(ip_counts.items(), key=lambda x: -x[1])
        top_ips = sorted_ips[:10]
        
        st.markdown("**🖥️ Top Endpoint IP Addresses:**")
        
        ip_col1, ip_col2 = st.columns(2)
        
        with ip_col1:
            # Table showing the top IPs and their packet count
            ip_df = pd.DataFrame(top_ips, columns=["IP Address", "Packet Count"])
            ip_df["Percentage"] = (ip_df["Packet Count"] / sum(ip_counts.values()) * 100).round(1)
            ip_df["Percentage"] = ip_df["Percentage"].astype(str) + "%"
            st.dataframe(ip_df, use_container_width=True, hide_index=True)
        
        with ip_col2:
            # Horizontal bar chart - easy to read IP addresses on the y-axis
            ip_bar_df = pd.DataFrame(top_ips, columns=["IP Address", "Packet Count"])
            fig_ip = px.bar(
                ip_bar_df,
                x="Packet Count",
                y="IP Address",
                orientation="h",  # Horizontal bars for better readability
                title="Top 10 Endpoint IP Addresses",
                color="Packet Count",
                color_continuous_scale="Blues"
            )
            fig_ip.update_layout(yaxis=dict(autorange="reversed"))  # Highest on top
            st.plotly_chart(fig_ip, use_container_width=True)
    
    st.markdown("")  # Spacer
    
    # ── Main Protocols ──
    st.markdown("**📡 Main Protocols:**")
    
    # Count how many packets per protocol
    protocol_counts = {}
    for pkt in packets:
        proto = get_protocol_name(pkt)
        protocol_counts[proto] = protocol_counts.get(proto, 0) + 1
    
    # Sort from highest to lowest
    sorted_protocols = sorted(protocol_counts.items(), key=lambda x: -x[1])
    
    # Display as a table
    proto_df = pd.DataFrame(sorted_protocols, columns=["Protocol", "Packet Count"])
    proto_df["Percentage"] = (proto_df["Packet Count"] / len(packets) * 100).round(1)
    proto_df["Percentage"] = proto_df["Percentage"].astype(str) + "%"
    
    col1, col2 = st.columns(2)
    with col1:
        st.dataframe(proto_df, use_container_width=True, hide_index=True)
    with col2:
        # Pie chart - shows the protocol distribution
        fig_pie = px.pie(
            proto_df,
            names="Protocol",
            values="Packet Count",
            title="Protocol Distribution",
            hole=0.3  # hole > 0 turns it into a donut chart
        )
        st.plotly_chart(fig_pie, use_container_width=True)
    
    st.markdown("---")
    
    # ══════════════════════════════════════════════════════════════════════
    # Section 26: Filtering option - traffic over time & protocol distribution
    # ══════════════════════════════════════════════════════════════════════
    st.subheader("📈 Visualizations & Filtering")
    
    # ── Traffic over time chart ──
    # Collect timestamps of all packets
    timestamps = [datetime.fromtimestamp(float(pkt.time)) for pkt in packets]
    sizes = [len(pkt) for pkt in packets]  # Size of each packet in bytes
    protocols = [get_protocol_name(pkt) for pkt in packets]
    
    # Create a DataFrame with all the data
    traffic_df = pd.DataFrame({
        "timestamp": timestamps,
        "size": sizes,
        "protocol": protocols,
    })
    
    # ── Filter by protocol ──
    st.markdown("**🔍 Filter by Protocol:**")
    all_protocols = sorted(traffic_df["protocol"].unique())
    
    # multiselect - allows choosing multiple protocols to filter by
    selected_protocols = st.multiselect(
        "Select protocols to display (leave empty for all)",
        options=all_protocols,
        default=[]  # Default - show all
    )
    
    # Filter if the user selected specific protocols
    if selected_protocols:
        filtered_df = traffic_df[traffic_df["protocol"].isin(selected_protocols)]
    else:
        filtered_df = traffic_df
    
    # ── Traffic over time chart ──
    # Group by seconds to see the rate
    if len(filtered_df) > 0:
        # resample - groups data by time windows
        # 's' = one second
        time_series = filtered_df.set_index("timestamp").resample("s")["size"].sum().reset_index()
        time_series.columns = ["Time", "Volume (bytes)"]
        
        fig_traffic = px.line(
            time_series,
            x="Time",
            y="Volume (bytes)",
            title="📊 Traffic Volume Over Time (bytes per second)",
            labels={"Time": "Time", "Volume (bytes)": "Volume (Bytes)"}
        )
        fig_traffic.update_layout(hovermode="x unified")
        st.plotly_chart(fig_traffic, use_container_width=True)
        
        # ── Bar chart - packets per protocol ──
        proto_bar = filtered_df["protocol"].value_counts().reset_index()
        proto_bar.columns = ["Protocol", "Packet Count"]
        
        fig_bar = px.bar(
            proto_bar,
            x="Protocol",
            y="Packet Count",
            title="📊 Packet Count by Protocol",
            color="Protocol"
        )
        st.plotly_chart(fig_bar, use_container_width=True)
    else:
        st.warning("No packets match the selected filter.")
    
    st.markdown("---")
    
    # =================================================================
    # Part 2: HTTP Transaction Recovery (Sections 27-29)
    # =================================================================
    st.header("🔄 HTTP Transactions")
    st.markdown("""
    > This section **automatically** finds HTTP requests and matching responses,
    > and allows you to view the full details of each transaction.
    """)
    
    # ── Section 27: Automatically find HTTP requests and matching responses ──
    with st.spinner("🔍 Searching for HTTP transactions..."):
        transactions = extract_http_transactions(packets)
    
    if len(transactions) > 0:
        st.success(f"✅ Found **{len(transactions)}** HTTP transactions")
        
        # ── Section 28: Display details of each transaction ──
        # Create a table with all transactions
        trans_df = pd.DataFrame(transactions)
        
        # Columns to display in the main table
        display_cols = ["method", "uri", "host", "src_ip", "dst_ip", "status_code", "response_time_ms", "req_frame", "resp_frame"]
        display_names = {
            "method": "Method",
            "uri": "URI",
            "host": "Host",
            "src_ip": "Source IP",
            "dst_ip": "Destination IP",
            "status_code": "Status Code",
            "response_time_ms": "Response Time (ms)",
            "req_frame": "Request Frame",
            "resp_frame": "Response Frame",
        }
        
        # Display the table with readable column names
        display_df = trans_df[display_cols].rename(columns=display_names)
        st.dataframe(display_df, use_container_width=True, hide_index=True)
        
        # ── Section 29: Select a transaction and view its details ──
        st.subheader("🔎 Selected Transaction Details")
        st.markdown("Choose a transaction from the list to see all its details:")
        
        # Create a list of options to choose from
        # Each option shows the method, URI, and host
        transaction_options = []
        for i, t in enumerate(transactions):
            label = f"#{i+1} | {t['method']} {t['host']}{t['uri']} | Status: {t['status_code']}"
            transaction_options.append(label)
        
        # selectbox - select one transaction from the list
        selected_idx = st.selectbox(
            "Choose a transaction:",
            range(len(transaction_options)),
            format_func=lambda i: transaction_options[i]
        )
        
        if selected_idx is not None:
            t = transactions[selected_idx]
            
            # Display all details in two columns
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("**📤 Request Details:**")
                st.markdown(f"- **Method:** `{t['method']}`")
                st.markdown(f"- **URI:** `{t['uri']}`")
                st.markdown(f"- **Host:** `{t['host']}`")
                st.markdown(f"- **Source (Client):** `{t['src_ip']}:{t['src_port']}`")
                st.markdown(f"- **Destination (Server):** `{t['dst_ip']}:{t['dst_port']}`")
                st.markdown(f"- **Frame Number:** `{t['req_frame']}`")
                if t['req_timestamp']:
                    st.markdown(f"- **Timestamp:** `{datetime.fromtimestamp(t['req_timestamp']).strftime('%H:%M:%S.%f')}`")
            
            with col2:
                st.markdown("**📥 Response Details:**")
                st.markdown(f"- **Status Code:** `{t['status_code']}`")
                if t['response_time_ms'] is not None:
                    st.markdown(f"- **Response Time:** `{t['response_time_ms']} ms`")
                else:
                    st.markdown("- **Response Time:** `No response found`")
                if t['resp_frame']:
                    st.markdown(f"- **Frame Number:** `{t['resp_frame']}`")
                else:
                    st.markdown("- **Frame Number:** `Not found`")
                if t['resp_timestamp']:
                    st.markdown(f"- **Timestamp:** `{datetime.fromtimestamp(t['resp_timestamp']).strftime('%H:%M:%S.%f')}`")
    else:
        st.info("ℹ️ No HTTP transactions found in this file.")
    
    st.markdown("---")
    
    # =================================================================
    # Part 3: AI-Powered Questions (Sections 30-34)
    # =================================================================
    st.header("🤖 AI-Powered Questions")
    st.markdown("""
    > Ask free-form questions about the capture!
    > The AI will analyze the data and respond with **evidence** (proof from the data).
    >
    > **Example questions:**
    > - Which request was the slowest?
    > - What Status Code was returned?
    > - How many requests were sent to a specific Host?
    > - What happened in the selected Stream?
    """)
    
    # ── Section 30: A place to write a question in free-form language ──
    # Input field for the Gemini API Key
    api_key = st.text_input(
        "🔑 Enter your Gemini API Key:",
        type="password",  # Hides the text
        help="You can get a free key from Google AI Studio: https://aistudio.google.com/app/apikey"
    )
    
    # Question input field
    user_question = st.text_area(
        "💬 Write your question:",
        placeholder="For example: Which HTTP request was the slowest? What was its Status Code?",
        height=100
    )
    
    # Submit button
    if st.button("🚀 Ask the AI", type="primary"):
        if not api_key:
            st.error("❌ Please enter a Gemini API Key")
        elif not user_question:
            st.error("❌ Please write a question")
        else:
            # Build the context - all the information the AI needs
            with st.spinner("📝 Preparing data summary..."):
                context = build_packet_summary(packets)
                
                # Also add the HTTP transactions
                if transactions:
                    context += "\n\n=== HTTP Transactions ===\n"
                    for i, t in enumerate(transactions):
                        context += (f"Transaction #{i+1}: {t['method']} {t['host']}{t['uri']} "
                                   f"| Status: {t['status_code']} "
                                   f"| Response Time: {t['response_time_ms']}ms "
                                   f"| Request Frame: {t['req_frame']} "
                                   f"| Response Frame: {t['resp_frame']}\n")
            
            # Send to AI
            with st.spinner("🤖 The AI is thinking..."):
                answer = ask_ai(user_question, context, api_key)
            
            # Display the answer
            st.markdown("### 📋 AI Response:")
            st.markdown(answer)
            
            # ── Section 32: Display evidence ──
            st.info("💡 Note: The AI bases its answers solely on the capture data and provides evidence such as Frame numbers and timestamps.")
    
    # ── Sections 33-34: Validation questions ──
    with st.expander("🧪 Validation Questions (Sections 33-34)"):
        st.markdown("""
        **As required by the assignment (Section 33):**  
        Test 5 questions that you already know the answers to from the manual part,
        and compare the results.
        
        **Example validation questions:**
        1. How many total packets are in the capture?
        2. Which HTTP request was the slowest?
        3. What was the Status Code of the first request?
        4. Which Host received the most requests?
        5. How long did the capture last?
        
        **Section 34:** If the AI makes a mistake, don't panic!  
        Document the error, explain why it happened,
        and describe how you fixed the system or the prompt.
        """)

else:
    # If no file has been uploaded yet - show instructions
    st.info("👆 Upload a PCAP or PCAPNG file to get started")
    
    # Display the dashboard structure
    st.markdown("""
    ### What the Dashboard Displays:
    
    | Section | Description | Clauses |
    |---------|-------------|---------|
    | 📂 Load Capture | Upload a PCAP file → general info, protocols, charts | 23-26 |
    | 🔄 HTTP Transactions | Find requests & responses, transaction details | 27-29 |
    | 🤖 AI Questions | Free-form questions with evidence | 30-34 |
    """)
