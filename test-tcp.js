const net = require('net');
const host = '34.77.59.254';
const port = 27017;

console.log(`Testing TCP connection to ${host}:${port}...`);

const socket = new net.Socket();
socket.setTimeout(5000);

socket.on('connect', () => {
  console.log('✅ TCP connection successful!');
  socket.end();
});

socket.on('timeout', () => {
  console.log('❌ TCP connection timed out');
  socket.destroy();
});

socket.on('error', (err) => {
  console.log(`❌ TCP connection error: ${err.message}`);
});

socket.on('close', () => {
  console.log('Connection closed');
});

socket.connect(port, host);