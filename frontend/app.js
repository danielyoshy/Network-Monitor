const ws = new WebSocket("ws://localhost:8000/ws/packets");
const statusEl = document.getElementById("status");
const logBody = document.getElementById("logBody");

ws.onopen = () => {
  statusEl.innerText = "Connected (Streaming)";
  statusEl.className = "connected";
};

ws.onclose = () => {
  statusEl.innerText = "Disconnected";
  statusEl.className = "disconnected";
};

ws.onmessage = (event) => {
  const packet = JSON.parse(event.data);
  
  // Create table row
  const row = document.createElement("tr");
  
  row.innerHTML = `
    <td class="badge ${packet.protocol.toLowerCase()}">${packet.protocol}</td>
    <td>${packet.src}</td>
    <td>${packet.dst}</td>
    <td>${packet.length}</td>
  `;

  // Insert at top of table
  logBody.insertBefore(row, logBody.firstChild);

  // Maintain log length limit for UI performance
  if (logBody.children.length > 50) {
    logBody.removeChild(logBody.lastChild);
  }
};
