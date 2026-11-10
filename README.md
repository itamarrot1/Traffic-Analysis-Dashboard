# 🔍 PCAP Traffic Analysis Dashboard

A lightweight, interactive web dashboard built with **Streamlit** and **Scapy** to inspect and analyze network packet capture files (`.pcap` / `.pcapng`).

---

## 🚀 Quick Start Guide

### 1. Prerequisites
* **Python 3.10+** installed on your system.
* **Npcap** installed (required for packet decoding on Windows — usually included if you have Wireshark installed).

### 2. Installation
Clone the repository (or navigate to the extracted project folder) and install the required dependencies:

```bash
git clone <repository-url>
cd pcap-dashboard

pip install -r requirements.txt
```

### 3. Running the Dashboard
Launch the Streamlit app:

```bash
streamlit run app.py
```

Your default web browser will automatically open at `http://localhost:8501`.

---

## 📖 How to Use the Dashboard

### 1. Load a Capture File
* Click **"Browse files"** or drag-and-drop any `.pcap` or `.pcapng` file into the upload box.
* The dashboard will automatically parse all packets and display:
  * **General Metrics:** Total packet count, start/end timestamps, and capture duration.
  * **Top Endpoint IP Addresses:** Most active IP addresses (source & destination) in a table and horizontal bar chart.
  * **Protocol Distribution:** Table and pie/donut chart breakdown of all detected protocols.
  * **Interactive Visualizations:** Traffic volume over time (bytes/sec) and protocol filters.

### 2. HTTP Transactions
* The dashboard reconstructs full HTTP transactions by pairing each request with its corresponding response using the TCP stream.
* **Overview Table:** Displays Method, URI, Host, IPs, Status Code, Response Time, and Frame numbers.
* **Transaction Details:** Select any specific transaction from the dropdown to inspect request/response headers, timestamps, and frame IDs.

### 3. AI-Powered Questions (Optional)
* Scroll down to the **"AI-Powered Questions"** section.
* Enter a free **Gemini API Key** (obtainable instantly at [Google AI Studio](https://aistudio.google.com/app/apikey)).
* Ask any question in plain English or Hebrew (e.g., *"Which HTTP request was the slowest?"*, *"What status codes were returned?"*).
* The AI will analyze the capture summary and respond citing **concrete evidence** (frame numbers and timestamps).

---

## 📁 Project Structure

```
pcap-dashboard/
├── app.py              # Main Streamlit application
├── requirements.txt    # Python dependencies
└── README.md           # Project documentation
```
