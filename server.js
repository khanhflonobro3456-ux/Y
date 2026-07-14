// server.js — VantaShield v1.0 (Render edition)
// Исправленная версия: полные маршруты, стили и HTML-обёртка.
// Причина отказа на Render: неполный package.json (нет geoip-lite, helmet, express-session, node-fetch).
// Код ниже полностью готов к деплою.

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
  } catch (e) { return false; }
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
  if (record.blockedUntil > now) return res.status(429).end();
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
  const check = (val) => {
    if (typeof val !== 'string') return false;
    return maliciousPatterns.some(p => p.test(val));
  };
  for (let k in req.query) if (check(req.query[k])) return res.status(403).end();
  if (req.body) {
    for (let k in req.body) {
      if (typeof req.body[k] === 'string' && check(req.body[k])) return res.status(403).end();
    }
  }
  for (let k in req.params) if (check(req.params[k])) return res.status(403).end();
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
  if (badUserAgents.some(p => p.test(ua))) return res.status(403).end();
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

// --------------------- МАСТЕР-IP ---------------------
let MASTER_IP = null;
const IP_FILE = './master_ip.json';

try {
  if (fs.existsSync(IP_FILE)) {
    const data = JSON.parse(fs.readFileSync(IP_FILE, 'utf8'));
    MASTER_IP = data.masterIP;
  }
} catch(e) {}

let BLOCK_ALL = false;

app.use((req, res, next) => {
  const clientIP = getClientIP(req);

  if (MASTER_IP === null && clientIP && clientIP !== '0.0.0.0') {
    MASTER_IP = clientIP;
    try { fs.writeFileSync(IP_FILE, JSON.stringify({ masterIP: MASTER_IP })); } catch(e) {}
  }

  const isPublic = PUBLIC_ROUTES.some(r => req.path.startsWith(r)) ||
                   req.path.match(/\.(css|js|png|jpg|jpeg|gif|svg|ico)$/);
  if (isPublic) return next();

  if (BLOCK_ALL && clientIP !== MASTER_IP) return res.status(403).end();
  if (clientIP !== MASTER_IP) return res.status(403).send('Доступ запрещён. Разрешён только мастер-устройству.');

  next();
});

// --------------------- EXPRESS И СЕССИИ ---------------------
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(express.json({ limit: '50mb' }));
app.use(express.static(__dirname));
app.use(session({
  secret: process.env.SESSION_SECRET || 'vantashield-secret-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 * 24 * 7 }
}));

// --------------------- JSON-БАЗЫ ---------------------
const DB_FILE = './vantashield_scripts.json';
const USERS_FILE = './vantashield_users.json';
const APIS_FILE = './vantashield_apis.json';
const PING_FILE = './vantashield_ping.json';

function loadJSON(file) {
  try { if (fs.existsSync(file)) return JSON.parse(fs.readFileSync(file, 'utf8')); } catch(e) {}
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
  const c = req.headers.cookie || '';
  const m = c.match(new RegExp('(^| )' + name + '=([^;]+)'));
  return m ? decodeURIComponent(m[2]) : null;
}
function escapeHTML(s) {
  return s ? s.replace(/[&<>'"]/g, t => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[t])) : '';
}
function isRobloxExecutor(req) {
  const ua = (req.headers['user-agent'] || '').toLowerCase();
  return ua.includes('roblox') || ua.includes('rblx') || !ua.includes('mozilla') ||
         ua.includes('synapse') || ua.includes('krnl') || ua.includes('fluxus') ||
         ua.includes('delta') || ua.includes('hydrogen') || ua.includes('codex') || ua.includes('arceus');
}
function getFreePort() {
  let maxPort = 8000;
  apisDb.forEach(a => { if (a.port && a.port >= maxPort) maxPort = a.port + 1; });
  return maxPort;
}
const runningProcesses = {};

async function doFetch(url) {
  if (typeof fetch === 'function') return fetch(url, {method:'GET', headers:{'User-Agent':'VantaShield-Ping/1.0'}, redirect:'follow'});
  const nodeFetch = require('node-fetch');
  return nodeFetch(url, {method:'GET', headers:{'User-Agent':'VantaShield-Ping/1.0'}, redirect:'follow'});
}

// --------------------- СТИЛИ И ШАБЛОН ---------------------
const style = `<style>@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Orbitron:wght@400;700;900&display=swap');
body.mobf-root{--vs-bg:#030303;--vs-card:#0a0a0a;--vs-border:#1f1f1f;--vs-border-hover:#333;--vs-text:#888;--vs-text-light:#e0e0e0;--vs-white:#fff;--vs-black:#000;background:var(--vs-bg);color:var(--vs-text-light);font-family:"JetBrains Mono",monospace;min-height:100vh;margin:0;overflow-x:hidden;position:relative}
.mobf-root::before{content:"";position:fixed;inset:0;background-image:linear-gradient(rgba(255,255,255,0.02)1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,0.02)1px,transparent 1px);background-size:40px 40px;animation:gridMove 20s linear infinite;pointer-events:none;z-index:0}
@keyframes gridMove{to{transform:translateY(40px)}}
.orb{position:fixed;border-radius:50%;filter:blur(100px);opacity:.03;pointer-events:none;z-index:0;animation:orbFloat 10s ease-in-out infinite}
.orb1{width:500px;height:500px;background:#fff;top:-100px;left:-100px}
.orb2{width:450px;height:450px;background:#fff;bottom:-150px;right:-100px;animation-delay:-3s}
.orb3{width:300px;height:300px;background:#fff;top:40%;left:30%;animation-delay:-6s;opacity:.01}
@keyframes orbFloat{0%,100%{transform:translate(0,0) scale(1)}50%{transform:translate(30px,-30px) scale(1.1)}}
.mobf-nav{position:sticky;top:0;z-index:100;display:flex;align-items:center;justify-content:space-between;padding:16px 32px;background:rgba(3,3,3,.85);backdrop-filter:blur(16px);border-bottom:1px solid var(--vs-border)}
.nav-logo{font-family:Orbitron,sans-serif;font-size:22px;font-weight:900;letter-spacing:2px;color:var(--vs-white);text-decoration:none;display:flex;align-items:center;gap:8px}
.menu-toggle{font-size:24px;background:0 0;border:none;color:var(--vs-white);cursor:pointer;display:flex;align-items:center}
.menu-toggle:hover{color:var(--vs-text);transform:scale(1.1)}
.sidebar{position:fixed;top:0;left:-300px;width:280px;height:100vh;background:#050505;border-right:1px solid var(--vs-border);z-index:999;padding:30px 20px;box-sizing:border-box;transition:all .4s cubic-bezier(.77,0,.175,1);box-shadow:10px 0 30px rgba(0,0,0,.9)}
.sidebar.active{left:0}
.sidebar-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:30px;font-family:Orbitron;font-weight:700;color:var(--vs-text-light)}
.sidebar-close{background:0 0;border:none;color:var(--vs-text);font-size:20px;cursor:pointer;display:flex}
.sidebar-close:hover{color:var(--vs-white)}
.sidebar-menu a{display:flex;align-items:center;gap:12px;padding:14px 18px;color:var(--vs-text);text-decoration:none;border-radius:8px;margin-bottom:5px;transition:.3s;font-weight:700}
.sidebar-menu a i{font-size:18px}
.sidebar-menu a:hover{background:rgba(255,255,255,.05);color:var(--vs-white)}
.user-badge{background:rgba(255,255,255,.02);padding:12px;border-radius:8px;font-size:12px;margin-bottom:20px;border:1px solid var(--vs-border);text-align:center;color:var(--vs-text)}
.hero{position:relative;z-index:1;text-align:center;padding:40px 20px 20px;max-width:860px;margin:0 auto}
.hero-badge{display:inline-flex;align-items:center;gap:8px;padding:6px 16px;border:1px solid var(--vs-border-hover);border-radius:20px;font-size:11px;letter-spacing:2px;text-transform:uppercase;color:var(--vs-text-light);margin-bottom:20px;background:rgba(255,255,255,.02)}
.hero h1{font-family:Orbitron,sans-serif;font-size:clamp(26px,5vw,42px);font-weight:900;letter-spacing:2px;margin:0 0 10px;color:var(--vs-white)}
.center-card-wrap{position:relative;z-index:1;max-width:800px;margin:0 auto 80px;padding:0 20px}
.quick-card{background:var(--vs-card);border:1px solid var(--vs-border);border-radius:12px;padding:32px;position:relative;overflow:hidden;box-shadow:0 10px 40px rgba(0,0,0,.8)}
.header-flex{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;flex-wrap:wrap;gap:10px}
.field-label{font-size:13px;letter-spacing:2px;text-transform:uppercase;color:var(--vs-text-light);font-weight:700;margin:0 0 10px;display:block}
.quick-card input[type=text],.quick-card input[type=password]{width:100%;padding:14px;background:var(--vs-black);border:1px solid var(--vs-border);border-radius:8px;color:var(--vs-white);font-family:"JetBrains Mono",monospace;font-size:14px;box-sizing:border-box;outline:0;transition:all .3s;margin-bottom:20px}
.quick-card input:focus,.quick-card textarea:focus{border-color:var(--vs-text);box-shadow:0 0 15px rgba(255,255,255,.05)}
.btn-upload{background:rgba(255,255,255,.02);color:var(--vs-text);border:1px dashed var(--vs-border-hover);padding:10px 15px;border-radius:8px;font-size:12px;cursor:pointer;transition:all .3s;font-family:Orbitron;display:inline-flex;align-items:center;gap:8px;font-weight:700}
.btn-upload:hover{background:rgba(255,255,255,.05);color:var(--vs-white);border-color:var(--vs-text)}
input[type=file]{display:none}
.quick-card textarea{width:100%;height:250px;background:var(--vs-black);border:1px solid var(--vs-border);border-radius:8px;color:var(--vs-text-light);font-family:"JetBrains Mono",monospace;font-size:13px;padding:14px;box-sizing:border-box;outline:0;transition:all .3s;resize:none;margin-bottom:15px}
.btn-save{width:100%;padding:16px;border:none;border-radius:8px;font-family:Orbitron;font-size:15px;font-weight:900;letter-spacing:2px;cursor:pointer;color:var(--vs-black);background:var(--vs-white);transition:all .2s;text-decoration:none;display:flex;align-items:center;justify-content:center;gap:10px;box-sizing:border-box}
.btn-save:hover{background:var(--vs-text-light);transform:translateY(-2px);box-shadow:0 8px 25px rgba(255,255,255,.15)}
.result-box{margin-top:15px;padding:20px;border-radius:8px;background:var(--vs-black);border:1px solid var(--vs-border);text-align:left;position:relative}
.copy-btn{position:absolute;top:10px;right:10px;background:var(--vs-border);color:var(--vs-text-light);border:1px solid var(--vs-border-hover);padding:8px 16px;border-radius:6px;font-size:12px;font-weight:700;cursor:pointer;font-family:Orbitron;transition:.3s}
.copy-btn:hover{background:var(--vs-white);color:var(--vs-black)}
.code-preview{color:var(--vs-text-light);word-break:break-all;font-size:13px;line-height:1.5;margin-top:10px;white-space:pre-wrap}
.manage-wrap{overflow-x:auto;width:100%}
.manage-table{width:100%;min-width:600px;border-collapse:collapse;margin-top:15px;font-size:13px}
.manage-table th{background:rgba(255,255,255,.02);color:var(--vs-text-light);padding:12px;text-align:left;border-bottom:1px solid var(--vs-border);font-family:Orbitron}
.manage-table td{padding:14px 12px;border-bottom:1px solid rgba(255,255,255,.02);vertical-align:middle}
.btn-action{padding:6px 10px;border:1px solid var(--vs-border);border-radius:6px;font-family:"JetBrains Mono";cursor:pointer;font-weight:700;font-size:11px;text-decoration:none;margin-right:5px;display:inline-flex;align-items:center;gap:6px;margin-bottom:5px;background:var(--vs-black);color:var(--vs-text-light);transition:.2s}
.btn-action:hover{border-color:var(--vs-text);color:var(--vs-white)}
.btn-delete:hover{border-color:#ef4444;color:#ef4444}
.badge-admin{background:var(--vs-white);color:var(--vs-black);padding:2px 6px;border-radius:4px;font-size:10px;font-weight:700}
.alert{padding:15px;background:rgba(255,255,255,.05);border:1px solid var(--vs-border);color:var(--vs-text-light);border-radius:8px;margin-bottom:20px;text-align:center;font-weight:700}
.alert-success{background:rgba(255,255,255,.1);border:1px solid var(--vs-text);color:var(--vs-white)}
.tos-list{text-align:left;margin-top:20px}
.tos-item{margin-bottom:25px;padding-bottom:15px;border-bottom:1px solid var(--vs-border)}
.tos-title{font-family:Orbitron;font-size:16px;color:var(--vs-white);margin-bottom:8px;font-weight:700}
.tos-title span{color:var(--vs-text);margin-right:8px}
.tos-desc{font-size:14px;color:var(--vs-text);line-height:1.6}
</style>`;

const baseHTML = (content, userSession = null) => {
  const isAdmin = userSession === 'master1';
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>VantaShield.com | Protected Hub</title>${style}</head>
<body class="mobf-root">
  <div class="orb orb1"></div><div class="orb orb2"></div><div class="orb orb3"></div>
  <nav class="mobf-nav">
    <a href="/" class="nav-logo"><i class="ph-fill ph-shield-check"></i> VANTASHIELD.COM</a>
    <button class="menu-toggle" onclick="toggleSidebar()"><i class="ph ph-list"></i></button>
  </nav>
  <div class="sidebar" id="sidebarNav">
    <div class="sidebar-header">
      <span>NAVIGATION</span>
      <button class="sidebar-close" onclick="toggleSidebar()"><i class="ph ph-x"></i></button>
    </div>
    ${userSession ? `
    <div class="user-badge">
      <div style="display:flex;justify-content:center;align-items:center;gap:6px;margin-bottom:8px"><i class="ph-fill ph-check-circle" style="color:var(--vs-white)"></i> Logged in as:</div>
      <b style="color:var(--vs-white);font-size:16px;display:flex;justify-content:center;align-items:center;gap:6px">${escapeHTML(userSession).toUpperCase()} ${isAdmin ? '<i class="ph-fill ph-crown"></i>' : ''}</b>
    </div>
    <div class="sidebar-menu">
      <a href="/"><i class="ph ph-house"></i> Creator Home</a>
      <a href="/dashboard"><i class="ph ph-file-code"></i> Script Management</a>
      <a href="/api-hosting"><i class="ph ph-cloud-arrow-up"></i> Tạo Web (Hosting)</a>
      <a href="/ping"><i class="ph ph-pulse"></i> Ping Monitor</a>
      <a href="/tos"><i class="ph ph-scroll"></i> Terms of Service</a>
      <a href="/logout" style="color:var(--vs-text);margin-top:40px"><i class="ph ph-sign-out"></i> Logout</a>
    </div>
    ` : `
    <div class="user-badge"><i class="ph-fill ph-x-circle" style="margin-right:6px"></i> Not Logged In</div>
    <div class="sidebar-menu" style="text-align:center">
      <p style="font-size:12px;color:var(--vs-text);margin-bottom:15px">Log in to securely save, edit, and manage your scripts globally.</p>
      <a href="/login" style="background:var(--vs-white);color:var(--vs-black);font-size:13px;margin-bottom:10px;justify-content:center"><i class="ph ph-key"></i> Login</a>
      <a href="/register" style="background:var(--vs-border);color:var(--vs-white);font-size:13px;margin-bottom:20px;justify-content:center"><i class="ph ph-user-plus"></i> Create Account</a>
      <div style="border-top:1px solid var(--vs-border);padding-top:10px">
        <a href="/api-hosting"><i class="ph ph-cloud-arrow-up"></i> Tạo Web (Hosting)</a>
        <a href="/tos" style="color:var(--vs-text)"><i class="ph ph-scroll"></i> Terms of Service</a>
      </div>
    </div>
    `}
  </div>
  <main>${content}</main>
  <script>
    function toggleSidebar(){document.getElementById('sidebarNav').classList.toggle('active')}
    function handleFileUpload(e){const f=e.target.files[0];if(!f)return;const r=new FileReader();r.onload=function(e){document.getElementById('codeArea').value=e.target.result};r.readAsText(f)}
    function copyText(id,btn){const t=document.getElementById(id).innerText;const ta=document.createElement('textarea');ta.value=t;document.body.appendChild(ta);ta.select();try{document.execCommand('copy');btn.innerHTML='<i class="ph ph-check"></i> COPIED!';btn.style.background='var(--vs-white)';btn.style.color='var(--vs-black)';setTimeout(()=>{btn.innerHTML='<i class="ph ph-copy"></i> COPY';btn.style.background='var(--vs-border)';btn.style.color='var(--vs-text-light)'},2000)}catch(e){}document.body.removeChild(ta)}
    function copyApiLink(name,btn){const url=window.location.origin+'/app/'+name;const ta=document.createElement('textarea');ta.value=url;document.body.appendChild(ta);ta.select();try{document.execCommand('copy');btn.innerHTML='<i class="ph ph-check"></i> COPIED!';btn.style.borderColor='var(--vs-white)';btn.style.color='var(--vs-white)';setTimeout(()=>{btn.innerHTML='<i class="ph ph-copy"></i> COPY LINK';btn.style.borderColor='var(--vs-border)';btn.style.color='var(--vs-text-light)'},2000)}catch(e){}document.body.removeChild(ta)}
    function openApiLink(name){window.open(window.location.origin+'/app/'+name,'_blank')}
  </script>
  <script src="https://unpkg.com/@phosphor-icons/web"></script>
</body></html>`;
};

// --------------------- ВСПОМОГАТЕЛЬНЫЙ РОУТ BLOCK_ALL (скрыт с UI) ---------------------
app.post('/toggle-block', (req, res) => {
  const user = getCookie(req, 'user_session');
  if (user !== 'master1') return res.status(403).send('Unauthorized');
  BLOCK_ALL = !BLOCK_ALL;
  res.json({ blocked: BLOCK_ALL });
});

// --------------------- ОСНОВНЫЕ РОУТЫ ---------------------

// Главная
app.get('/', (req, res) => {
  const user = getCookie(req, 'user_session');
  res.send(baseHTML(`
    <section class="hero"><div class="hero-badge"><i class="ph-fill ph-shield-check"></i> BRAND NEW RAW SYSTEM WITH ANTI-SKID</div><h1><span class="line2">RAW HUB CODESHARE</span></h1></section>
    <div class="center-card-wrap"><div class="quick-card"><form action="/create" method="POST"><div class="header-flex"><label class="field-label"><i class="ph ph-file-code"></i> SCRIPT CONTENT (LUA / TXT)</label><label class="btn-upload"><i class="ph ph-upload-simple"></i> UPLOAD FILE...<input type="file" accept=".lua,.txt,.luau,.js" onchange="handleFileUpload(event)"></label></div><textarea id="codeArea" name="code" placeholder="-- Type your script here..." required></textarea><label class="field-label" style="margin-top:15px"><i class="ph ph-text-t"></i> CUSTOM FILE NAME (OPTIONAL)</label><input type="text" name="fileName" placeholder="auto-farm" pattern="[a-zA-Z0-9-_]+"><button type="submit" class="btn-save"><i class="ph-fill ph-lock-key"></i> SECURE & GENERATE RAW LINK</button></form></div></div>
  `, user));
});

app.post('/create', (req, res) => {
  const user = getCookie(req, 'user_session') || 'guest_anonymous';
  const { code, fileName } = req.body;
  const id = crypto.randomBytes(4).toString('hex');
  const safeFileName = (fileName && fileName.trim()) ? fileName.trim().replace(/[^a-zA-Z0-9_-]/g, '') : id;
  const rawCreatorName = user === 'guest_anonymous' ? 'anonymous' : user;
  db.set(id, { code, owner: user, fileName: safeFileName, createdAt: Date.now() });
  saveDb();
  const host = req.get('host');
  const protocol = req.headers['x-forwarded-proto'] || req.protocol;
  const rawLink = `${protocol}://${host}/${rawCreatorName}/${safeFileName}/refs/heads/main/${safeFileName}`;
  const loadstringCommand = `loadstring(game:HttpGet("${rawLink}"))()`;
  res.send(baseHTML(`
    <section class="hero"><h1><span class="line2">RAW GENERATED!</span></h1></section>
    <div class="center-card-wrap" style="max-width:650px"><div class="quick-card"><div class="result-box"><div style="font-size:11px;color:var(--vs-text)"><i class="ph ph-terminal"></i> EXECUTOR LOADSTRING:</div><button type="button" class="copy-btn" onclick="copyText('loadstring-text', this)"><i class="ph ph-copy"></i> COPY</button><div class="code-preview" id="loadstring-text">${loadstringCommand}</div></div><br><a href="/" class="btn-save" style="background:var(--vs-black);color:var(--vs-text-light);border:1px solid var(--vs-border)"><i class="ph ph-plus"></i> CREATE ANOTHER</a></div></div>
  `, user === 'guest_anonymous' ? null : user));
});

// Регистрация и вход
app.get('/register', (req, res) => {
  const err = req.query.error;
  res.send(baseHTML(`<section class="hero"><h1><span class="line2">CREATE NEW ACCOUNT</span></h1></section>
    <div class="center-card-wrap" style="max-width:450px"><div class="quick-card">${err ? `<div class="alert"><i class="ph-fill ph-warning"></i> ${escapeHTML(err)}</div>` : ''}
    <form action="/register" method="POST"><label class="field-label"><i class="ph ph-user"></i> USERNAME</label><input type="text" name="username" placeholder="Enter username..." required minlength="3"><label class="field-label"><i class="ph ph-lock-key"></i> PASSWORD</label><input type="password" name="password" placeholder="Enter password..." required minlength="4"><button type="submit" class="btn-save" style="margin-top:10px"><i class="ph ph-user-plus"></i> REGISTER NOW</button></form>
    <div style="text-align:center;margin-top:20px;font-size:13px;color:var(--vs-text)">Already have an account? <a href="/login" style="color:var(--vs-white);font-weight:bold">Login here</a></div></div></div>`));
});

app.post('/register', (req, res) => {
  const { username, password } = req.body;
  const clean = username.trim().toLowerCase();
  if (clean === 'master1' || usersDb.has(clean)) return res.redirect('/register?error=Username already exists!');
  usersDb.set(clean, { password });
  saveUsers();
  res.redirect('/login?success=Registration successful! Please login.');
});

app.get('/login', (req, res) => {
  const error = req.query.error, success = req.query.success;
  res.send(baseHTML(`<section class="hero"><h1><span class="line2">SYSTEM LOGIN</span></h1></section>
    <div class="center-card-wrap" style="max-width:450px"><div class="quick-card">${error ? `<div class="alert"><i class="ph-fill ph-warning"></i> ${escapeHTML(error)}</div>` : ''}${success ? `<div class="alert alert-success"><i class="ph-fill ph-check-circle"></i> ${escapeHTML(success)}</div>` : ''}
    <form action="/login" method="POST"><label class="field-label"><i class="ph ph-user"></i> USERNAME</label><input type="text" name="username" placeholder="Enter username..." required><label class="field-label"><i class="ph ph-lock-key"></i> PASSWORD</label><input type="password" name="password" placeholder="Enter password..." required><button type="submit" class="btn-save" style="margin-top:10px"><i class="ph ph-sign-in"></i> ACCESS SYSTEM</button></form>
    <div style="text-align:center;margin-top:20px;font-size:13px;color:var(--vs-text)">Don't have an account? <a href="/register" style="color:var(--vs-white);font-weight:bold">Register here</a></div></div></div>`));
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const clean = username.trim().toLowerCase();
  const user = usersDb.get(clean);
  if (user && user.password === password) {
    res.cookie('user_session', clean, { maxAge: 1000 * 60 * 60 * 24 * 7, httpOnly: true });
    res.redirect('/');
  } else {
    res.redirect('/login?error=Invalid username or password!');
  }
});

app.get('/logout', (req, res) => {
  res.clearCookie('user_session');
  res.redirect('/');
});

// Дашборд
app.get('/dashboard', (req, res) => {
  const user = getCookie(req, 'user_session');
  if (!user) return res.redirect('/login?error=Please login.');
  const isAdmin = user === 'master1';
  const SEVEN_DAYS = 7 * 24 * 60 * 60 * 1000, now = Date.now();
  let rows = '';
  db.forEach((val, key) => {
    const age = now - (val.createdAt || now);
    if (val.owner === 'master1' && age > SEVEN_DAYS) return;
    if (isAdmin || val.owner === user) {
      rows += `<tr><td style="font-weight:bold;font-family:'JetBrains Mono'">${val.fileName || key}</td>${isAdmin ? `<td><span class="badge-admin">${val.owner.toUpperCase()}</span></td>` : ''}<td style="max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escapeHTML(val.code.substring(0,35))}...</td><td><a href="/edit/${key}" class="btn-action"><i class="ph ph-pencil-simple"></i> EDIT</a><a href="/delete/${key}" class="btn-action btn-delete" onclick="return confirm('Confirm delete?')"><i class="ph ph-trash"></i> DEL</a>${isAdmin ? `<a href="/download/${key}" class="btn-action"><i class="ph ph-download-simple"></i> DL</a>` : ''}</td></tr>`;
    }
  });
  res.send(baseHTML(`<section class="hero"><h1><span class="line2">${isAdmin ? 'MASTER DASHBOARD' : 'SCRIPT MANAGEMENT'}</span></h1></section>
    <div class="center-card-wrap" style="max-width:900px"><div class="quick-card"><div class="field-label"><i class="ph ph-folder-open"></i> ${isAdmin ? 'ALL SYSTEM SCRIPTS' : `CODES FOR [${escapeHTML(user.toUpperCase())}]:`}</div><div class="manage-wrap"><table class="manage-table"><thead><tr><th>SCRIPT ID / NAME</th>${isAdmin?'<th>OWNER</th>':''}<th>PREVIEW</th><th>ACTIONS</th></tr></thead><tbody>${rows || `<tr><td colspan="${isAdmin?4:3}" style="text-align:center;padding:20px;color:var(--vs-text)">No scripts found.</td></tr>`}</tbody></table></div></div></div>`, user));
});

app.get('/download/:id', (req, res) => {
  const user = getCookie(req, 'user_session');
  if (user !== 'master1') return res.status(403).send("Admin only.");
  const data = db.get(req.params.id);
  if (!data) return res.status(404).send("Not found.");
  res.setHeader('Content-disposition', `attachment; filename=vantashield_${data.fileName||req.params.id}.lua`);
  res.setHeader('Content-type', 'text/plain; charset=utf-8');
  res.send(data.code);
});

app.get('/edit/:id', (req, res) => {
  const user = getCookie(req, 'user_session');
  const isAdmin = user === 'master1';
  const id = req.params.id;
  const data = db.get(id);
  if (!data || (!isAdmin && data.owner !== user)) return res.send("Invalid permissions.");
  const rawCreatorName = data.owner === 'guest_anonymous' ? 'anonymous' : data.owner;
  const safeFileName = data.fileName || id;
  const host = req.get('host');
  const protocol = req.headers['x-forwarded-proto'] || req.protocol;
  const rawLink = `${protocol}://${host}/${rawCreatorName}/${safeFileName}/refs/heads/main/${safeFileName}`;
  const loadstringCommand = `loadstring(game:HttpGet("${rawLink}"))()`;
  res.send(baseHTML(`<section class="hero"><h1><span class="line2">EDIT SCRIPT [${id}]</span></h1></section>
    <div class="center-card-wrap"><div class="quick-card"><div class="result-box" style="margin-top:0;margin-bottom:25px"><div style="font-size:11px;color:var(--vs-white);font-weight:bold;font-family:'Orbitron'">LOADSTRING COMMAND:</div><button type="button" class="copy-btn" onclick="copyText('loadstring-text-edit', this)"><i class="ph ph-copy"></i> COPY</button><div class="code-preview" id="loadstring-text-edit" style="color:#fff">${loadstringCommand}</div></div>
    <form action="/edit/${id}" method="POST"><div style="background:rgba(255,255,255,.02);padding:15px;border-radius:8px;border:1px solid var(--vs-border);margin-bottom:20px"><label class="field-label"><i class="ph ph-upload-simple"></i> UPLOAD NEW FILE</label><label class="btn-upload" style="background:var(--vs-white);color:var(--vs-black);border:none"><i class="ph ph-folder-open"></i> SELECT FILE...<input type="file" accept=".lua,.txt,.luau,.js" onchange="handleFileUpload(event)"></label></div>
    <div class="field-label">DIRECT EDIT</div><textarea id="codeArea" name="code" required>${escapeHTML(data.code)}</textarea><button type="submit" class="btn-save"><i class="ph ph-floppy-disk"></i> SAVE CHANGES</button></form></div></div>`, user));
});

app.post('/edit/:id', (req, res) => {
  const user = getCookie(req, 'user_session');
  const isAdmin = user === 'master1';
  const id = req.params.id;
  const data = db.get(id);
  if (data && (isAdmin || data.owner === user)) {
    data.code = req.body.code;
    db.set(id, data);
    saveDb();
  }
  res.redirect('/dashboard');
});

app.get('/delete/:id', (req, res) => {
  const user = getCookie(req, 'user_session');
  const isAdmin = user === 'master1';
  const id = req.params.id;
  const data = db.get(id);
  if (data && (isAdmin || data.owner === user)) {
    db.delete(id);
    saveDb();
  }
  res.redirect('/dashboard');
});

// Хостинг API
app.get('/api-hosting', (req, res) => {
  const user = getCookie(req, 'user_session');
  if (!user) return res.redirect('/login?error=Bạn cần đăng nhập để sử dụng API Hosting.');
  const isAdmin = user === 'master1';
  let rowsHtml = '';
  apisDb.forEach((val, key) => {
    if (isAdmin || val.owner === user) {
      const stCol = val.status==='ONLINE'?'var(--vs-white)':'var(--vs-text)';
      const stIcon = val.status==='ONLINE'?'<i class="ph-fill ph-check-circle"></i>':'<i class="ph-fill ph-x-circle"></i>';
      rowsHtml += `<tr><td style="color:var(--vs-white);font-weight:bold">${escapeHTML(val.name)}</td>
        ${isAdmin?`<td><span class="badge-admin">${val.owner.toUpperCase()}</span></td>`:''}
        <td><span style="color:${stCol};font-weight:bold;display:flex;align-items:center;gap:6px">${stIcon} ${val.status}</span></td>
        <td style="color:var(--vs-text);font-family:'JetBrains Mono'">/app/${val.name}</td>
        <td>${val.status==='ONLINE'?`
          <button class="btn-action" onclick="openApiLink('${val.name}')"><i class="ph ph-arrow-square-out"></i> MỞ WEB</button>
          <button class="btn-action" onclick="copyApiLink('${val.name}', this)"><i class="ph ph-copy"></i> COPY LINK</button>
          <form action="/api-action/stop/${key}" method="POST" style="display:inline"><button type="submit" class="btn-action"><i class="ph ph-stop-circle"></i> STOP</button></form>
        `:`<form action="/api-action/start/${key}" method="POST" style="display:inline"><button type="submit" class="btn-action" style="color:var(--vs-white);border-color:var(--vs-text)"><i class="ph ph-play-circle"></i> START</button></form>`}
        <form action="/api-action/delete/${key}" method="POST" style="display:inline" onsubmit="return confirm('Bạn có chắc muốn xóa Web này vĩnh viễn?');"><button type="submit" class="btn-action btn-delete"><i class="ph ph-trash"></i> XÓA</button></form></td></tr>`;
    }
  });
  const msg = req.query.msg;
  res.send(baseHTML(`<section class="hero"><div class="hero-badge"><i class="ph ph-cloud"></i> VANTASHIELD CLOUD PLATFORM</div><h1><span class="line2">TẠO WEB (HOSTING)</span></h1></section>
    ${msg?`<div class="center-card-wrap"><div class="alert alert-success"><i class="ph-fill ph-check-circle"></i> ${escapeHTML(msg)}</div></div>`:''}
    <div class="center-card-wrap" style="max-width:1000px;display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:20px">
      <div class="quick-card" style="padding:25px"><div class="field-label" style="color:var(--vs-white);font-size:15px;text-align:center"><i class="ph ph-github-logo" style="font-size:28px;display:block;margin-bottom:8px"></i> DEPLOY TỪ GITHUB</div>
      <form id="githubForm" onsubmit="handleAjaxDeploy(event,'github')"><label class="field-label">TÊN DỰ ÁN</label><input type="text" name="project_name" placeholder="my-github-web" required pattern="[a-z0-9-]+"><label class="field-label">LINK KHO GITHUB</label><input type="text" name="repo_url" placeholder="https://github.com/user/repo.git" required><button type="submit" class="btn-save" style="margin-top:10px"><i class="ph ph-rocket-launch"></i> DEPLOY</button></form></div>
      <div class="quick-card" style="padding:25px"><div class="field-label" style="color:var(--vs-white);font-size:15px;text-align:center"><i class="ph ph-terminal-window" style="font-size:28px;display:block;margin-bottom:8px"></i> TẠO TRỰC TIẾP</div>
      <form id="manualForm" onsubmit="handleAjaxDeploy(event,'manual')"><label class="field-label">TÊN DỰ ÁN</label><input type="text" name="project_name" placeholder="my-local-web" required pattern="[a-z0-9-]+"><label class="field-label">package.json</label><textarea name="pkg_json" style="height:80px;font-family:monospace">{"name":"my-web","version":"1.0.0","main":"server.js","dependencies":{"express":"^4.19.2"}}</textarea><label class="field-label">server.js</label><textarea name="srv_js" style="height:120px;font-family:monospace">const express=require('express');const app=express();app.get('/',(req,res)=>res.send('<h1>Web thành công!</h1>'));app.listen(process.env.PORT||3000);</textarea><button type="submit" class="btn-save"><i class="ph ph-hammer"></i> TẠO WEB</button></form></div>
    </div>
    <div class="center-card-wrap" style="max-width:1000px"><div class="quick-card"><div class="field-label"><i class="ph ph-hard-drives"></i> CÁC WEB CỦA BẠN</div><div class="manage-wrap"><table class="manage-table"><thead><tr><th>TÊN</th>${isAdmin?'<th>CHỦ SỞ HỮU</th>':''}<th>TRẠNG THÁI</th><th>ĐƯỜNG DẪN</th><th>HÀNH ĐỘNG</th></tr></thead><tbody>${rowsHtml||'<tr><td colspan="'+(isAdmin?5:4)+'" style="text-align:center;padding:20px;color:var(--vs-text)">Chưa có web nào.</td></tr>'}</tbody></table></div></div></div>
    <script>async function handleAjaxDeploy(e,type){e.preventDefault();const form=e.target,data=Object.fromEntries(new FormData(form));let endpoint=type==='github'?'/api-deploy-github-ajax':'/api-deploy-ajax';try{const res=await fetch(endpoint,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});const result=await res.json();if(result.success){setTimeout(()=>window.location.href='/api-hosting?msg=Tạo web thành công!',500)}else alert(result.message)}catch(err){alert('Lỗi kết nối.')}}</script>`, user));
});

// API deploy
app.post('/api-deploy-ajax', async (req, res) => {
  const user = getCookie(req, 'user_session');
  if (!user) return res.json({success:false, message:'Chưa đăng nhập.'});
  let {project_name, pkg_json, srv_js} = req.body;
  project_name = project_name.trim().toLowerCase().replace(/[^a-z0-9-]/g,'');
  if (!project_name) return res.json({success:false, message:'Tên không hợp lệ.'});
  if (Array.from(apisDb.values()).some(a=>a.name===project_name)) return res.json({success:false, message:'Tên đã tồn tại.'});
  const apiId = crypto.randomBytes(4).toString('hex');
  const port = getFreePort();
  const apiDir = path.join(__dirname,'hosted_apis',apiId);
  try {
    if (!fs.existsSync(path.join(__dirname,'hosted_apis'))) fs.mkdirSync(path.join(__dirname,'hosted_apis'));
    fs.mkdirSync(apiDir,{recursive:true});
    fs.writeFileSync(path.join(apiDir,'package.json'), pkg_json);
    fs.writeFileSync(path.join(apiDir,'server.js'), srv_js);
    apisDb.set(apiId,{id:apiId, owner:user, name:project_name, port, status:'OFFLINE', createdAt:Date.now()});
    saveApis();
    exec('npm install',{cwd:apiDir},(err)=>{
      if(err) return res.json({success:false, message:'npm install lỗi'});
      startApiProcess(apiId);
      res.json({success:true, name:project_name});
    });
  } catch(e) { res.json({success:false, message:'Lỗi tạo file'}); }
});

app.post('/api-deploy-github-ajax', async (req, res) => {
  const user = getCookie(req, 'user_session');
  if (!user) return res.json({success:false, message:'Chưa đăng nhập.'});
  let {project_name, repo_url} = req.body;
  project_name = project_name.trim().toLowerCase().replace(/[^a-z0-9-]/g,'');
  if (!project_name) return res.json({success:false, message:'Tên không hợp lệ.'});
  repo_url = repo_url.trim();
  if (!repo_url.startsWith('http')||!repo_url.includes('github.com')) return res.json({success:false, message:'Link GitHub không hợp lệ.'});
  if (Array.from(apisDb.values()).some(a=>a.name===project_name)) return res.json({success:false, message:'Tên đã tồn tại.'});
  const apiId = crypto.randomBytes(4).toString('hex');
  const port = getFreePort();
  const apiDir = path.join(__dirname,'hosted_apis',apiId);
  try {
    if (!fs.existsSync(path.join(__dirname,'hosted_apis'))) fs.mkdirSync(path.join(__dirname,'hosted_apis'));
    fs.mkdirSync(apiDir,{recursive:true});
    exec(`git clone "${repo_url}" .`,{cwd:apiDir},(err)=>{
      if(err) return res.json({success:false, message:'Clone GitHub thất bại.'});
      apisDb.set(apiId,{id:apiId, owner:user, name:project_name, port, status:'OFFLINE', createdAt:Date.now()});
      saveApis();
      if(fs.existsSync(path.join(apiDir,'package.json'))) exec('npm install',{cwd:apiDir},()=>{startApiProcess(apiId);});
      else startApiProcess(apiId);
      res.json({success:true, name:project_name});
    });
  } catch(e) { res.json({success:false, message:'Lỗi hệ thống'}); }
});

function startApiProcess(apiId) {
  const api = apisDb.get(apiId);
  if(!api) return;
  const apiDir = path.join(__dirname,'hosted_apis',apiId);
  try {
    const child = spawn('node',['server.js'],{cwd:apiDir, env:{...process.env, PORT:api.port}});
    runningProcesses[apiId] = child;
    api.status = 'ONLINE';
    api.pid = child.pid;
    apisDb.set(apiId, api);
    saveApis();
    child.on('exit',()=>{
      if(apisDb.has(apiId)){
        let dbApi = apisDb.get(apiId);
        dbApi.status = 'OFFLINE';
        dbApi.pid = null;
        apisDb.set(apiId, dbApi);
        saveApis();
      }
      delete runningProcesses[apiId];
    });
  } catch(e) { console.error('start process error', e); }
}

app.post('/api-action/:action/:id', (req, res) => {
  const user = getCookie(req, 'user_session');
  const isAdmin = user==='master1';
  const {action, id} = req.params;
  const api = apisDb.get(id);
  if(!api||(!isAdmin&&api.owner!==user)) return res.redirect('/api-hosting');
  if(action==='stop' && runningProcesses[id]) {
    runningProcesses[id].kill();
    delete runningProcesses[id];
    api.status = 'OFFLINE';
    apisDb.set(id, api);
    saveApis();
    return res.redirect('/api-hosting?msg=Đã dừng Web.');
  } else if(action==='start' && !runningProcesses[id]) {
    startApiProcess(id);
    return res.redirect('/api-hosting?msg=Đã khởi động lại Web.');
  } else if(action==='delete') {
    if(runningProcesses[id]){ runningProcesses[id].kill(); delete runningProcesses[id]; }
    const apiDir = path.join(__dirname,'hosted_apis',id);
    if(fs.existsSync(apiDir)) fs.rmSync(apiDir,{recursive:true, force:true});
    apisDb.delete(id);
    saveApis();
    return res.redirect('/api-hosting?msg=Đã xóa Web.');
  }
  res.redirect('/api-hosting');
});

// Ping monitor
async function pingAll() {
  const jobs = [];
  pingDb.forEach((entry)=>{
    jobs.push((async()=>{
      const start = Date.now();
      try {
        const r = await doFetch(entry.url);
        entry.lastStatus = r.status;
        entry.lastOk = r.ok;
        entry.lastTime = Date.now()-start;
        entry.lastCheck = Date.now();
        entry.totalPings = (entry.totalPings||0)+1;
        if(r.ok) entry.successCount = (entry.successCount||0)+1;
      } catch(e) {
        entry.lastStatus = 0;
        entry.lastOk = false;
        entry.lastTime = Date.now()-start;
        entry.lastCheck = Date.now();
        entry.lastError = String(e.message||e).slice(0,120);
        entry.totalPings = (entry.totalPings||0)+1;
      }
    })());
  });
  await Promise.allSettled(jobs);
  safeWriteFile(PING_FILE, Object.fromEntries(pingDb));
}
setInterval(()=>{pingAll().catch(()=>{});},10000);

app.get('/ping', (req, res) => {
  const user = getCookie(req, 'user_session');
  if(!user) return res.redirect('/login?error=Cần đăng nhập.');
  const mine = [];
  pingDb.forEach((v,k)=>{ if(v.owner===user) mine.push({id:k,...v}); });
  const rows = mine.map(m=>{
    const status = m.lastOk?'ONLINE':(m.lastCheck?'DOWN':'PENDING');
    const color = m.lastOk?'var(--vs-white)':(m.lastCheck?'#ef4444':'var(--vs-text)');
    const uptime = m.totalPings?Math.round((m.successCount||0)/m.totalPings*100):0;
    return `<tr><td style="font-family:'JetBrains Mono'">${escapeHTML(m.url)}</td><td><span style="color:${color};font-weight:bold">${status} ${m.lastStatus?'('+m.lastStatus+')':''}</span></td><td>${m.lastTime||0}ms</td><td>${uptime}% (${m.successCount||0}/${m.totalPings||0})</td><td>${m.lastCheck?new Date(m.lastCheck).toLocaleTimeString():'-'}</td><td><form action="/ping/delete/${m.id}" method="POST" style="display:inline"><button class="btn-action btn-delete"><i class="ph ph-trash"></i> XÓA</button></form></td></tr>`;
  }).join('');
  res.send(baseHTML(`<section class="hero"><div class="hero-badge"><i class="ph ph-pulse"></i> UPTIME MONITOR</div><h1><span class="line2">PING MONITOR</span></h1></section>
    <div class="center-card-wrap" style="max-width:1000px"><div class="quick-card"><form action="/ping/add" method="POST"><label class="field-label"><i class="ph ph-link"></i> URL CẦN PING</label><input type="text" name="url" placeholder="https://example.com" required><button type="submit" class="btn-save"><i class="ph ph-plus-circle"></i> THÊM</button></form></div>
    <div class="quick-card" style="margin-top:20px"><div class="field-label"><i class="ph ph-list-checks"></i> DANH SÁCH URL</div><div class="manage-wrap"><table class="manage-table"><thead><tr><th>URL</th><th>STATUS</th><th>THỜI GIAN</th><th>UPTIME</th><th>PING GẦN NHẤT</th><th>HÀNH ĐỘNG</th></tr></thead><tbody>${rows||'<tr><td colspan="6" style="text-align:center;padding:20px;color:var(--vs-text)">Chưa có URL nào.</td></tr>'}</tbody></table></div></div></div>
    <script>setTimeout(()=>location.reload(),10000);</script>`, user));
});

app.post('/ping/add', (req, res) => {
  const user = getCookie(req, 'user_session');
  if(!user) return res.redirect('/login');
  let url = (req.body.url||'').trim();
  if(!/^https?:\/\//i.test(url)) url = 'https://'+url;
  try{new URL(url);}catch(e){return res.redirect('/ping');}
  const id = crypto.randomBytes(4).toString('hex');
  pingDb.set(id,{owner:user, url, createdAt:Date.now(), totalPings:0, successCount:0});
  safeWriteFile(PING_FILE, Object.fromEntries(pingDb));
  res.redirect('/ping');
});

app.post('/ping/delete/:id', (req, res) => {
  const user = getCookie(req, 'user_session');
  const entry = pingDb.get(req.params.id);
  if(entry && (entry.owner===user||user==='master1')){
    pingDb.delete(req.params.id);
    safeWriteFile(PING_FILE, Object.fromEntries(pingDb));
  }
  res.redirect('/ping');
});

// ToS
app.get('/tos', (req, res) => {
  const user = getCookie(req, 'user_session');
  res.send(baseHTML(`<section class="hero"><div class="hero-badge"><i class="ph ph-gavel"></i> LEGAL</div><h1><span class="line2">TERMS OF SERVICE</span></h1></section>
    <div class="center-card-wrap" style="max-width:800px"><div class="quick-card"><div class="tos-list"><div class="tos-item"><div class="tos-title"><span>01 //</span> Redistribution</div><div class="tos-desc">You are not permitted to redistribute scripts without permission.</div></div><div class="tos-item"><div class="tos-title"><span>02 //</span> Acceptable Use</div><div class="tos-desc">You must not use this service for malicious purposes.</div></div><div class="tos-item"><div class="tos-title"><span>03 //</span> Ownership</div><div class="tos-desc">All code snippets remain the sole property of their respective creators.</div></div></div></div></div>`, user));
});

// --------------------- RAW SCRIPT & ANTI-SKID ---------------------
app.all('/:creatorName/:fileName/refs/heads/main/:fileName2', (req, res) => {
  const {creatorName, fileName} = req.params;
  let data = null;
  for (const [key, val] of db.entries()) {
    const vc = val.owner==='guest_anonymous'?'anonymous':val.owner;
    if((val.fileName===fileName||key===fileName) && vc===creatorName){ data=val; break; }
  }
  if(isRobloxExecutor(req)){
    if(!data) return res.status(404).send('print("VantaShield: Script Not Found")');
    res.setHeader('Content-Type','text/plain; charset=utf-8');
    return res.send(data.code);
  }
  if(!data) return res.send(`<!DOCTYPE html><html><head><meta charset="UTF-8"><title>404</title>${style}</head><body><div class="troll-screen"><div class="troll-text">SKID ALERT !</div><div class="troll-sub">Code does not exist.</div></div><script>setTimeout(()=>window.location.href="https://www.google.com",3000);</script></body></html>`);
  return res.send(`<!DOCTYPE html><html><head><meta charset="UTF-8"><title>SKID DETECTED</title>${style}</head><body><div class="troll-screen"><div class="troll-text">SKID ALERT !</div><div class="troll-sub">Get out! Stealing source code is strictly prohibited.</div></div><script>setTimeout(()=>window.location.href="https://www.google.com",3000);</script></body></html>`);
});

app.all('/v1/:id', (req, res) => {
  const id = req.params.id;
  const data = db.get(id);
  if(isRobloxExecutor(req)){
    if(!data) return res.status(404).send('print("VantaShield: Script Not Found")');
    res.setHeader('Content-Type','text/plain; charset=utf-8');
    return res.send(data.code);
  }
  if(!data) return res.send(`<!DOCTYPE html><html><head><meta charset="UTF-8"><title>404</title>${style}</head><body><div class="troll-screen"><div class="troll-text">SKID ALERT !</div><div class="troll-sub">Code does not exist.</div></div><script>setTimeout(()=>window.location.href="https://www.google.com",3000);</script></body></html>`);
  return res.send(`<!DOCTYPE html><html><head><meta charset="UTF-8"><title>SKID DETECTED</title>${style}</head><body><div class="troll-screen"><div class="troll-text">SKID ALERT !</div><div class="troll-sub">Get out!</div></div><script>setTimeout(()=>window.location.href="https://www.google.com",3000);</script></body></html>`);
});

// --------------------- ЗАПУСК ---------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`[VantaShield] Сервер запущен на порту ${PORT}`);
});
