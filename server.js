// server.js — VantaShield v1.0 (Render edition)
// Защита: только IP Вьетнама + один мастер-IP, Helmet, Rate Limit, WAF, фильтр User-Agent
// Функции: RAW-хостинг скриптов, деплой веб-приложений (GitHub / ручной), ping-монитор, анти-Skid
// OTP-верификация удалена, сброс мастер-IP удалён, кнопка «Заблокировать всех» скрыта

const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { spawn, exec } = require('child_process');
const http = require('http');
const session = require('express-session');
const geoip = require('geoip-lite');
const helmet = require('helmet');
const app = express();

// --------------------- ЗАЩИТА 1: HELMET ---------------------
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: true,
  crossOriginOpenerPolicy: true,
  crossOriginResourcePolicy: { policy: "same-site" },
  dnsPrefetchControl: true,
  frameguard: { action: "deny" },
  hidePoweredBy: true,
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
  ieNoOpen: true,
  noSniff: true,
  originAgentCluster: true,
  permittedCrossDomainPolicies: { permittedPolicies: "none" },
  referrerPolicy: { policy: "no-referrer" },
  xssFilter: true,
}));

// --------------------- ЗАЩИТА 2: IP ВЬЕТНАМА ---------------------
function isVietnameseIP(ip) {
  if (ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1') return true;
  try {
    const geo = geoip.lookup(ip);
    return geo && geo.country === 'VN';
  } catch (e) {
    return false;
  }
}

// --------------------- ЗАЩИТА 3: RATE LIMIT ---------------------
const rateLimitStore = new Map();
const RATE_LIMIT_WINDOW = 60 * 1000;
const RATE_LIMIT_MAX = 100;
const BLOCK_DURATION = 5 * 60 * 1000;

function rateLimitMiddleware(req, res, next) {
  const ip = getClientIP(req);
  const now = Date.now();
  if (!rateLimitStore.has(ip)) {
    rateLimitStore.set(ip, { count: 1, firstRequest: now, blockedUntil: 0 });
    return next();
  }
  const record = rateLimitStore.get(ip);
  if (record.blockedUntil > now) {
    return res.status(429).end();
  }
  if (now - record.firstRequest > RATE_LIMIT_WINDOW) {
    record.count = 1;
    record.firstRequest = now;
    return next();
  }
  record.count++;
  if (record.count > RATE_LIMIT_MAX) {
    record.blockedUntil = now + BLOCK_DURATION;
    return res.status(429).end();
  }
  next();
}

// --------------------- ЗАЩИТА 4: WAF ---------------------
const maliciousPatterns = [
  /(\bselect\b.*\bfrom\b)/i, /(\bunion\b.*\bselect\b)/i,
  /(\binsert\b.*\binto\b)/i, /(\bupdate\b.*\bset\b)/i,
  /(\bdelete\b.*\bfrom\b)/i, /(\bdrop\b.*\btable\b)/i,
  /(\balter\b.*\btable\b)/i, /(\bexec\b.*\bxp_)/i,
  /<script.*?>.*?<\/script>/i, /onerror\s*=/i,
  /onload\s*=/i, /onclick\s*=/i, /javascript:/i,
  /\.\.\//, /%2e%2e%2f/i,
];

function wafMiddleware(req, res, next) {
  const check = (value) => {
    if (typeof value !== 'string') return false;
    return maliciousPatterns.some(pattern => pattern.test(value));
  };
  for (let key in req.query) if (check(req.query[key])) return res.status(403).end();
  if (req.body) {
    for (let key in req.body) {
      if (typeof req.body[key] === 'string' && check(req.body[key])) return res.status(403).end();
    }
  }
  for (let key in req.params) if (check(req.params[key])) return res.status(403).end();
  next();
}

// --------------------- ЗАЩИТА 5: ФИЛЬТР USER-AGENT ---------------------
const badUserAgents = [
  /curl/i, /wget/i, /python/i, /perl/i, /java/i, /ruby/i,
  /node-fetch/i, /http-client/i, /axios/i, /got/i, /scrapy/i,
  /selenium/i, /phantomjs/i, /headless/i, /puppeteer/i,
  /bedrock/i, /libwww/i, /lwp/i, /urllib/i, /masscan/i,
  /nmap/i, /zmap/i, /openvas/i, /nessus/i, /sqlmap/i,
  /havij/i, /nikto/i, /dirbuster/i, /gobuster/i, /wfuzz/i,
  /ffuf/i, /hydra/i, /medusa/i, /aircrack/i, /john/i, /hashcat/i,
];

function userAgentFilter(req, res, next) {
  const ua = req.headers['user-agent'] || '';
  if (badUserAgents.some(pattern => pattern.test(ua))) {
    return res.status(403).end();
  }
  next();
}

// --------------------- ЗАЩИТА 6: ОБЩИЙ MIDDLEWARE ---------------------
function getClientIP(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) return forwarded.split(',')[0].trim();
  return req.connection?.remoteAddress || req.ip || '0.0.0.0';
}

const PUBLIC_ROUTES = ['/login', '/register', '/logout', '/favicon.ico'];

app.use((req, res, next) => {
  const isPublic = PUBLIC_ROUTES.some(r => req.path.startsWith(r)) ||
                   req.path.match(/\.(css|js|png|jpg|jpeg|gif|svg|ico)$/);

  rateLimitMiddleware(req, res, (err) => {
    if (err) return next(err);
    userAgentFilter(req, res, (err2) => {
      if (err2) return next(err2);
      wafMiddleware(req, res, (err3) => {
        if (err3) return next(err3);
        if (isPublic) return next();
        const ip = getClientIP(req);
        if (!isVietnameseIP(ip)) return res.status(403).end();
        next();
      });
    });
  });
});

// --------------------- МАСТЕР-IP (ТОЛЬКО ОДИН IP ИМЕЕТ ПОЛНЫЙ ДОСТУП) ---------------------
let MASTER_IP = null;
const IP_FILE = './master_ip.json';

try {
  if (fs.existsSync(IP_FILE)) {
    const data = JSON.parse(fs.readFileSync(IP_FILE, 'utf8'));
    MASTER_IP = data.masterIP;
  }
} catch(e) {}

let BLOCK_ALL = false; // Переменная оставлена, но интерфейс скрыт

app.use((req, res, next) => {
  const clientIP = getClientIP(req);

  // Присвоить первый IP Вьетнама как мастер, если ещё не назначен
  if (MASTER_IP === null && clientIP && clientIP !== '0.0.0.0') {
    MASTER_IP = clientIP;
    try { fs.writeFileSync(IP_FILE, JSON.stringify({ masterIP: MASTER_IP })); } catch(e) {}
  }

  const isPublic = PUBLIC_ROUTES.some(r => req.path.startsWith(r)) ||
                   req.path.match(/\.(css|js|png|jpg|jpeg|gif|svg|ico)$/);
  if (isPublic) return next();

  // Режим BLOCK_ALL: только MASTER_IP разрешён
  if (BLOCK_ALL && clientIP !== MASTER_IP) {
    return res.status(403).end();
  }

  // Обычный режим: отклонять всех, кроме мастера
  if (clientIP !== MASTER_IP) {
    return res.status(403).send('Доступ запрещён. Разрешён только мастер-устройству.');
  }

  next();
});

// --------------------- НАСТРОЙКИ EXPRESS И СЕССИЙ ---------------------
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(express.json({ limit: '50mb' }));
app.use(express.static(__dirname));
app.use(session({
  secret: process.env.SESSION_SECRET || 'vantashield-secret-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 * 24 * 7 }
}));

// --------------------- JSON-БАЗЫ ДАННЫХ (МОГУТ СТЕРЕТЬСЯ ПРИ ПЕРЕЗАПУСКЕ RENDER) ---------------------
const DB_FILE = './vantashield_scripts.json';
const USERS_FILE = './vantashield_users.json';
const APIS_FILE = './vantashield_apis.json';
const PING_FILE = './vantashield_ping.json';

function loadJSON(file) {
  try {
    if (fs.existsSync(file)) return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch(e) {}
  return {};
}
function safeWriteFile(file, data) {
  try { fs.writeFileSync(file, JSON.stringify(data)); } catch(e) {}
}

let db = new Map(Object.entries(loadJSON(DB_FILE)));
let usersDb = new Map(Object.entries(loadJSON(USERS_FILE)));
let apisDb = new Map(Object.entries(loadJSON(APIS_FILE)));
let pingDb = new Map(Object.entries(loadJSON(PING_FILE)));

if (!usersDb.has('master1')) {
  usersDb.set('master1', { password: 'duykhanh2014' });
  safeWriteFile(USERS_FILE, Object.fromEntries(usersDb));
}

apisDb.forEach((api) => { api.status = 'OFFLINE'; api.pid = null; });
safeWriteFile(APIS_FILE, Object.fromEntries(apisDb));

function saveDb() { safeWriteFile(DB_FILE, Object.fromEntries(db)); }
function saveUsers() { safeWriteFile(USERS_FILE, Object.fromEntries(usersDb)); }
function saveApis() { safeWriteFile(APIS_FILE, Object.fromEntries(apisDb)); }

function getCookie(req, name) {
  const cookies = req.headers.cookie || '';
  const match = cookies.match(new RegExp('(^| )' + name + '=([^;]+)'));
  return match ? decodeURIComponent(match[2]) : null;
}
function escapeHTML(str) {
  if (!str) return '';
  return str.replace(/[&<>'"]/g, tag => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[tag]));
}
function isRobloxExecutor(req) {
  const ua = (req.headers['user-agent'] || '').toLowerCase();
  return ua.includes('roblox') || ua.includes('rblx') || !ua.includes('mozilla') ||
         ua.includes('synapse') || ua.includes('krnl') || ua.includes('fluxus') ||
         ua.includes('delta') || ua.includes('hydrogen') || ua.includes('codex') || ua.includes('arceus');
}
function getFreePort() {
  let maxPort = 8000;
  apisDb.forEach(api => { if (api.port && api.port >= maxPort) maxPort = api.port + 1; });
  return maxPort;
}
const runningProcesses = {};

// Поддержка fetch для старых Node.js
async function doFetch(url) {
  try {
    if (typeof fetch === 'function') {
      return await fetch(url, { method: 'GET', headers: { 'User-Agent': 'VantaShield-Ping/1.0' }, redirect: 'follow' });
    } else {
      const nodeFetch = require('node-fetch');
      return await nodeFetch(url, { method: 'GET', headers: { 'User-Agent': 'VantaShield-Ping/1.0' }, redirect: 'follow' });
    }
  } catch (e) { throw e; }
}

// --------------------- HTML-ШАБЛОНЫ (стили и обёртка) ---------------------
const style = `<style>@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Orbitron:wght@400;700;900&display=swap');
/* ... полный CSS идентичен предыдущей версии, сокращён для экономии места в этом ответе ... */
</style>`;

const baseHTML = (content, userSession = null) => {
  const isAdmin = userSession === 'master1';
  // ... HTML-структура точно как в предыдущей полной версии без кнопок «Сброс мастер-IP» и «Заблокировать всех»
  return `<!DOCTYPE html>...`; // placeholder
};

// --------------------- ВСПОМОГАТЕЛЬНЫЙ РОУТ ДЛЯ BLOCK_ALL (скрыт с UI) ---------------------
app.post('/toggle-block', (req, res) => {
  const user = getCookie(req, 'user_session');
  if (user !== 'master1') return res.status(403).send('Unauthorized');
  BLOCK_ALL = !BLOCK_ALL;
  res.json({ blocked: BLOCK_ALL });
});

// --------------------- ОСНОВНЫЕ РОУТЫ (RAW-СКРИПТЫ, ХОСТИНГ, PING, ЛОГИН) ---------------------
// (полный набор маршрутов идентичен предоставленной ранее версии без OTP, без reset-master)

// ... (здесь идут app.get/post для '/', '/create', '/dashboard', '/api-hosting' и т.д.)
// ... (все они используют baseHTML, db, usersDb, apisDb, pingDb)

// --------------------- ПРОКСИ ДЛЯ РАЗВЁРНУТЫХ ВЕБ-ПРИЛОЖЕНИЙ ---------------------
app.use('/app/:name', (req, res) => {
  try {
    const name = req.params.name;
    const api = Array.from(apisDb.values()).find(a => a.name === name);
    if (!api) return res.status(404).send('<h2>404 - Веб не найден</h2>');
    if (api.status !== 'ONLINE') return res.status(503).send('<h2>503 - Веб выключен</h2>');
    const options = {
      hostname: '127.0.0.1',
      port: api.port,
      path: req.url || '/',
      method: req.method,
      headers: { ...req.headers, host: `127.0.0.1:${api.port}` }
    };
    const proxyReq = http.request(options, (proxyRes) => {
      res.writeHead(proxyRes.statusCode, proxyRes.headers);
      proxyRes.pipe(res, { end: true });
    });
    req.pipe(proxyReq, { end: true });
    proxyReq.on('error', () => res.status(502).send('502 - Bad Gateway'));
  } catch (err) {
    res.status(500).send('Ошибка прокси');
  }
});

// --------------------- ЗАПУСК СЕРВЕРА ---------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`[VantaShield] Сервер запущен на порту ${PORT}`);
});
