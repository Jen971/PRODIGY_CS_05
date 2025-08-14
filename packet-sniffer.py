from scapy.all import sniff, IP, IPv6, ICMP, TCP, Raw, wrpcap
from flask import Flask, send_from_directory, render_template

from flask_socketio import SocketIO

import os
import datetime
import threading
import time

app = Flask(__name__)
socketio = SocketIO(app, async_mode='threading') 

sniffing_active = False
delay_seconds = 0
packets = []  #

@app.route('/')
def serve_index():
    return render_template('index.html')


@socketio.on('start_sniff')
def handle_start_sniff():
    global sniffing_active
    sniffing_active = True
    socketio.emit('sniffer_status', {'status': 'Sniffing started'})

@socketio.on('stop_sniff')
def handle_stop_sniff():
    global sniffing_active
    sniffing_active = False
    socketio.emit('sniffer_status', {'status': 'Sniffing stopped'})

@socketio.on('set_delay')
def handle_set_delay(data):
    global delay_seconds
    try:
        delay_seconds = float(data.get('delay', 0))
    except Exception:
        delay_seconds = 0
    socketio.emit('sniffer_status', {'status': f'Delay set to {delay_seconds} seconds'})

@socketio.on('clear_packets')
def handle_clear_packets():
    global packets
    packets.clear()
    socketio.emit('sniffer_status', {'status': 'Packets cleared'})
    socketio.emit('clear_ui')  
    socketio.emit('clear_ui')

@socketio.on('export_pcap')
def handle_export_pcap():
    global packets
    if not packets:
        socketio.emit('sniffer_status', {'status': 'No packets to export'})
        return

    export_path = os.path.join(os.getcwd(), 'exported_capture.pcap')
    wrpcap(export_path, packets)
    socketio.emit('sniffer_status', {'status': f'Exported {len(packets)} packets to exported_capture.pcap'})

def parse_packet(pkt):
    info = {}
    info['timestamp'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if IP in pkt:
        ip_layer = pkt[IP]
        info['SOURCE IP'] = ip_layer.src
        info['DESTINATION IP'] = ip_layer.dst
        proto_map = {1: "ICMPv4", 6: "TCP", 17: "UDP"}
        info['protocol'] = proto_map.get(ip_layer.proto, str(ip_layer.proto))
    elif IPv6 in pkt:
        ip6_layer = pkt[IPv6]
        info['SOURCE IP'] = ip6_layer.src
        info['DESTINATION IP'] = ip6_layer.dst
        proto_map = {58: "ICMPv6", 6: "TCP", 17: "UDP"}
        info['protocol'] = proto_map.get(ip6_layer.nh, str(ip6_layer.nh))
    else:
        return None

    if ICMP in pkt:
        info['protocol'] = "ICMPv4" if IP in pkt else "ICMPv6"

    payload_text = ""
    if Raw in pkt:
        raw_bytes = pkt[Raw].load
        try:
            payload_text = raw_bytes.decode('utf-8', errors='ignore').replace('\n', ' ').replace('\r', ' ').replace('\t', ' ')
            if len(payload_text) > 200:
                payload_text = payload_text[:200] + "..."
        except Exception:
            payload_text = "[binary data]"
    info['payload'] = payload_text

    if TCP in pkt:
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        if (sport in [80, 443] or dport in [80, 443]) and payload_text:
            info['protocol'] = "HTTP"

    return info

def packet_handler(pkt):
    global sniffing_active, delay_seconds, packets
    if not sniffing_active:
        return

    info = parse_packet(pkt)
    if info:
        packets.append(pkt)
        socketio.emit('new_packet', info)
        if delay_seconds > 0:
            time.sleep(delay_seconds)

def sniff_packets():
    sniff(prn=packet_handler, store=False)

if __name__ == '__main__':
    sniff_thread = threading.Thread(target=sniff_packets, daemon=True)
    sniff_thread.start()
    print("Starting Flask-SocketIO server... (Run as Administrator/root for packet capture)")
    socketio.run(app, host="127.0.0.1", port=5000, debug=True)
