## WireInspect Packet Sniffer 

A lightweight web-based packet sniffer built with **Python (Scapy)** and **Flask-SocketIO**. Capture and monitor network packets in real-time directly from your browser.

---

## Features

- Real-time packet capture (IP, TCP, UDP, ICMP, HTTP)
- Live updating table of packets with timestamp, source/destination IP, protocol, and payload
- Start/Stop sniffing with buttons
- Clear captured packets from the table
- Export captured packets as a **PCAP file**
- Stylish fire-themed dark UI for easy readability

---

## Installation

1. **Clone the repository:**
   git clone https://github.com/Jen971/PRODIGY_CS_05/
   cd packet-sniffer.
2. pip install scapy flask flask-socketio

3.Open your browser and go to:
   http://127.0.0.1:5000

## Usage ##
Click Start Sniffing to capture packets in real-time.
Click Stop Sniffing to pause capture.
Click Clear Packets to remove all captured packets from the table.
Click Export PCAP to save all captured packets to exported_capture.pcap.

## File Structure ##
packet-sniffer/
├─ packet-sniffer.py
├─ templates/
│  └─ index.html     
├─ static/
│  └─ script.js    
└─ README.md

## DEMO VIDEO ## 
(uploaded inside demo video0 folder)

## Screenshots ## 
https://github.com/Jen971/PRODIGY_CS_05/blob/039c80e6ae0cf69cda8a5d2c808910003d9bea0a/TASK5(1).png
https://github.com/Jen971/PRODIGY_CS_05/blob/039c80e6ae0cf69cda8a5d2c808910003d9bea0a/TASK5(2).png

