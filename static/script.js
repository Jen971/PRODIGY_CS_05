document.addEventListener('DOMContentLoaded', () => {
  const socket = io();

  const startBtn = document.getElementById('startBtn');
  const stopBtn = document.getElementById('stopBtn');
  const clearBtn = document.getElementById('clearBtn');
  const exportBtn = document.getElementById('exportBtn');
  const statusDiv = document.getElementById('status');
  const packetBody = document.getElementById('packetBody');

  startBtn.onclick = () => {
    socket.emit('start_sniff');
    startBtn.disabled = true;
    stopBtn.disabled = false;
    statusDiv.textContent = "Status: Sniffing started";
  };

  stopBtn.onclick = () => {
    socket.emit('stop_sniff');
    startBtn.disabled = false;
    stopBtn.disabled = true;
    statusDiv.textContent = "Status: Sniffing stopped";
  };

  clearBtn.onclick = () => {
    console.log("Clear packets button clicked");
    socket.emit('clear_packets');
  };

  exportBtn.onclick = () => {
    console.log("Export PCAP button clicked");
    socket.emit('export_pcap');
  };

  socket.on('sniffer_status', data => {
    statusDiv.textContent = "Status: " + data.status;
  });

  socket.on('new_packet', info => {
    const row = document.createElement('tr');

    const timestampCell = document.createElement('td');
    timestampCell.textContent = info.timestamp;
    row.appendChild(timestampCell);

    const srcCell = document.createElement('td');
    srcCell.textContent = info.src_ip;
    row.appendChild(srcCell);

    const dstCell = document.createElement('td');
    dstCell.textContent = info.dst_ip;
    row.appendChild(dstCell);

    const protoCell = document.createElement('td');
    protoCell.textContent = info.protocol;
    row.appendChild(protoCell);

    const payloadCell = document.createElement('td');
    payloadCell.textContent = info.payload;
    row.appendChild(payloadCell);

    packetBody.appendChild(row);
  });

  socket.on('clear_ui', () => {
    packetBody.innerHTML = '';
  });
});
