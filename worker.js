export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders() });
    }

    if (path === '/api/login' && request.method === 'POST') {
      return handleLogin(request, env);
    }

    if (path === '/api/logout' && request.method === 'POST') {
      return handleLogout();
    }

    const authed = await isAuthenticated(request, env);

    if (path.startsWith('/api/') && !authed) {
      return json({ error: '未登录' }, 401);
    }

    if (path === '/api/bookmarks') {
      if (request.method === 'GET') {
        const data = await env.NAV_KV.get('bookmarks', 'json');
        return json({ bookmarks: data || defaultBookmarks });
      }
      if (request.method === 'POST') {
        const body = await safeJson(request);
        if (!Array.isArray(body?.bookmarks)) {
          return json({ error: 'bookmarks 必须是数组' }, 400);
        }
        await env.NAV_KV.put('bookmarks', JSON.stringify(body.bookmarks));
        return json({ ok: true });
      }
    }

    if (path === '/api/bg') {
      if (request.method === 'GET') {
        const bg = await getBackground(env);
        return json(bg);
      }
      if (request.method === 'POST') {
        const body = await safeJson(request);
        if (body?.mode === 'manual') {
          if (!body.url || typeof body.url !== 'string') {
            return json({ error: '手动模式需要 url' }, 400);
          }
          await env.NAV_KV.put('bg:manual', body.url);
          return json({ ok: true, mode: 'manual', url: body.url });
        }
        if (body?.mode === 'auto') {
          await env.NAV_KV.delete('bg:manual');
          return json({ ok: true, mode: 'auto' });
        }
        return json({ error: 'mode 仅支持 manual/auto' }, 400);
      }
    }

    if (path === '/api/weather' && request.method === 'GET') {
      const lat = Number(url.searchParams.get('lat') || '31.23');
      const lon = Number(url.searchParams.get('lon') || '121.47');
      const weatherRes = await fetch(`https://api.open-meteo.com/v1/forecast?latitude=${lat}&longitude=${lon}&daily=weathercode,temperature_2m_max,temperature_2m_min&current=temperature_2m,weathercode&timezone=auto`);
      if (!weatherRes.ok) {
        return json({ error: '天气服务不可用' }, 502);
      }
      const data = await weatherRes.json();
      return json(data);
    }

    if (path === '/' || path === '/index.html') {
      if (!authed) {
        return html(loginPage());
      }
      return html(appPage());
    }

    return new Response('Not Found', { status: 404 });
  }
};

const defaultBookmarks = [
  { title: 'Cloudflare', url: 'https://dash.cloudflare.com/' },
  { title: 'GitHub', url: 'https://github.com/' },
  { title: 'OpenAI', url: 'https://platform.openai.com/' }
];

function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type'
  };
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      ...corsHeaders()
    }
  });
}

function html(body) {
  return new Response(body, {
    headers: { 'Content-Type': 'text/html; charset=utf-8' }
  });
}

async function safeJson(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

function getCookie(request, key) {
  const cookie = request.headers.get('Cookie') || '';
  return cookie
    .split(';')
    .map((v) => v.trim())
    .find((v) => v.startsWith(`${key}=`))
    ?.split('=')[1];
}

async function signValue(value, secret) {
  const msg = new TextEncoder().encode(`${value}:${secret}`);
  const hash = await crypto.subtle.digest('SHA-256', msg);
  const bytes = Array.from(new Uint8Array(hash));
  return bytes.map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function isAuthenticated(request, env) {
  const token = getCookie(request, 'session');
  if (!token || !env.ACCESS_PASSWORD || !env.SESSION_SECRET) return false;
  const expected = await signValue(env.ACCESS_PASSWORD, env.SESSION_SECRET);
  return token === expected;
}

async function handleLogin(request, env) {
  const body = await safeJson(request);
  const password = body?.password;
  if (!password) {
    return json({ error: '请输入密码' }, 400);
  }
  if (!env.ACCESS_PASSWORD || !env.SESSION_SECRET) {
    return json({ error: '服务端未配置 ACCESS_PASSWORD / SESSION_SECRET' }, 500);
  }
  if (password !== env.ACCESS_PASSWORD) {
    return json({ error: '密码错误' }, 401);
  }

  const token = await signValue(password, env.SESSION_SECRET);
  const res = json({ ok: true });
  res.headers.append('Set-Cookie', `session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=604800`);
  return res;
}

function handleLogout() {
  const res = json({ ok: true });
  res.headers.append('Set-Cookie', 'session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0');
  return res;
}

async function getBackground(env) {
  const manual = await env.NAV_KV.get('bg:manual');
  if (manual) {
    return { mode: 'manual', url: manual };
  }

  const date = new Date().toISOString().slice(0, 10);
  const key = `bg:auto:${date}`;
  let url = await env.NAV_KV.get(key);
  if (!url) {
    url = `https://picsum.photos/seed/${date.replaceAll('-', '')}/1920/1080`;
    await env.NAV_KV.put(key, url, { expirationTtl: 60 * 60 * 24 * 7 });
  }
  return { mode: 'auto', url };
}

function loginPage() {
  return `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>私有导航 - 登录</title>
  <style>
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      background: radial-gradient(circle at 20% 20%, #3f51b5, #111);
      font-family: Inter, system-ui, -apple-system, sans-serif;
      color: #fff;
    }
    .card {
      width: min(92vw, 420px);
      padding: 28px;
      border-radius: 18px;
      background: rgba(255, 255, 255, .12);
      backdrop-filter: blur(18px);
      border: 1px solid rgba(255, 255, 255, .2);
      box-shadow: 0 10px 30px rgba(0,0,0,.25);
      animation: pop .5s ease;
    }
    @keyframes pop {
      from { transform: scale(.95); opacity: 0; }
      to { transform: scale(1); opacity: 1; }
    }
    input, button {
      width: 100%;
      border: none;
      padding: 12px 14px;
      border-radius: 10px;
      margin-top: 10px;
      font-size: 14px;
    }
    button {
      cursor: pointer;
      font-weight: 600;
      background: linear-gradient(135deg, #7c4dff, #448aff);
      color: white;
    }
    #err { color: #ffb3b3; min-height: 20px; }
  </style>
</head>
<body>
  <div class="card">
    <h2>🔒 私有导航</h2>
    <p>请输入访问密码</p>
    <input id="pwd" type="password" placeholder="Password" />
    <button id="go">进入</button>
    <p id="err"></p>
  </div>
  <script>
    document.getElementById('go').onclick = async () => {
      const password = document.getElementById('pwd').value;
      const res = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password })
      });
      const data = await res.json();
      if (!res.ok) {
        document.getElementById('err').textContent = data.error || '登录失败';
        return;
      }
      location.href = '/';
    };
  </script>
</body>
</html>`;
}

function appPage() {
  return `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>私有导航与书签</title>
  <style>
    :root { color-scheme: dark; }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: Inter, system-ui, -apple-system, sans-serif;
      color: #fff;
      min-height: 100vh;
      background-size: cover;
      background-position: center;
      transition: background-image .5s ease;
    }
    #loader {
      position: fixed;
      inset: 0;
      display: grid;
      place-items: center;
      background: #050509;
      z-index: 9999;
      animation: fadeOut .8s ease 1.2s forwards;
    }
    #loader .ring {
      width: 64px; height: 64px;
      border: 4px solid rgba(255,255,255,.2);
      border-top-color: #7aa2ff;
      border-radius: 50%;
      animation: spin 1s linear infinite;
    }
    @keyframes spin { to { transform: rotate(360deg);} }
    @keyframes fadeOut { to { opacity: 0; visibility: hidden; } }

    .shell {
      min-height: 100vh;
      background: linear-gradient(to bottom, rgba(8,8,12,.25), rgba(8,8,12,.7));
      backdrop-filter: blur(4px);
      padding: 24px;
    }

    .glass {
      background: rgba(20, 20, 28, .42);
      border: 1px solid rgba(255,255,255,.2);
      border-radius: 16px;
      backdrop-filter: blur(16px);
      box-shadow: 0 8px 30px rgba(0,0,0,.2);
    }

    .header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      padding: 14px 16px;
      margin-bottom: 20px;
    }

    .tabs { display: flex; gap: 10px; }
    .tabs button {
      border: none;
      background: rgba(255,255,255,.12);
      color: #fff;
      padding: 9px 14px;
      border-radius: 999px;
      cursor: pointer;
    }
    .tabs button.active { background: rgba(122,162,255,.65); }

    .panel {
      display: none;
      padding: 16px;
      animation: tabIn .35s ease;
    }
    .panel.active { display: block; }
    @keyframes tabIn {
      from { opacity: 0; transform: translateY(12px) scale(.98); }
      to { opacity: 1; transform: translateY(0) scale(1); }
    }

    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
      gap: 12px;
    }

    .card {
      display: block;
      text-decoration: none;
      color: #fff;
      padding: 14px;
      border-radius: 12px;
      background: rgba(255,255,255,.1);
      border: 1px solid rgba(255,255,255,.18);
      backdrop-filter: blur(12px);
      transition: transform .25s ease, background .25s;
    }
    .card:hover {
      transform: translateY(-5px);
      background: rgba(255,255,255,.16);
    }

    .row { display: flex; gap: 10px; flex-wrap: wrap; }
    input, button {
      border: none;
      border-radius: 10px;
      padding: 10px 12px;
    }
    input {
      background: rgba(255,255,255,.13);
      color: #fff;
      min-width: 180px;
    }
    button { cursor: pointer; }

    .weather {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(110px, 1fr));
      gap: 10px;
      margin-top: 14px;
    }
    .weather .w {
      padding: 10px;
      border-radius: 10px;
      background: rgba(255,255,255,.08);
      text-align: center;
    }
  </style>
</head>
<body>
  <div id="loader"><div class="ring"></div></div>
  <div class="shell">
    <div class="header glass">
      <strong>🧭 私有导航 / 书签中心</strong>
      <div class="tabs">
        <button data-tab="nav" class="active">导航</button>
        <button data-tab="bookmark">书签</button>
        <button data-tab="weather">天气</button>
      </div>
      <button id="logout">退出</button>
    </div>

    <div id="nav" class="panel glass active">
      <div id="navGrid" class="grid"></div>
    </div>

    <div id="bookmark" class="panel glass">
      <div class="row">
        <input id="title" placeholder="标题" />
        <input id="link" placeholder="https://example.com" />
        <button id="add">添加书签</button>
      </div>
      <div id="bookGrid" class="grid" style="margin-top:12px"></div>
      <hr style="border-color:rgba(255,255,255,.15); margin:14px 0" />
      <div class="row">
        <input id="bgUrl" placeholder="手动背景 URL" style="min-width:320px" />
        <button id="setBg">设为手动背景</button>
        <button id="setAuto">切回每日自动背景</button>
      </div>
    </div>

    <div id="weather" class="panel glass">
      <div class="row">
        <input id="lat" placeholder="纬度(如 31.23)" />
        <input id="lon" placeholder="经度(如 121.47)" />
        <button id="loadWeather">刷新天气</button>
      </div>
      <div id="weatherBox" class="weather"></div>
    </div>
  </div>

  <script>
    const tabs = document.querySelectorAll('[data-tab]');
    tabs.forEach((btn) => {
      btn.onclick = () => {
        tabs.forEach((b) => b.classList.remove('active'));
        btn.classList.add('active');
        document.querySelectorAll('.panel').forEach((p) => p.classList.remove('active'));
        document.getElementById(btn.dataset.tab).classList.add('active');
      };
    });

    async function api(path, options = {}) {
      const res = await fetch(path, options);
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || '请求失败');
      return data;
    }

    let bookmarks = [];

    function renderCards(target, list) {
      target.innerHTML = '';
      list.forEach((item) => {
        const a = document.createElement('a');
        a.className = 'card';
        a.href = item.url;
        a.target = '_blank';
        a.rel = 'noreferrer';
        a.innerHTML = '<strong>' + item.title + '</strong><div style="opacity:.75;margin-top:6px;font-size:12px">' + item.url + '</div>';
        target.appendChild(a);
      });
    }

    async function loadBookmarks() {
      const data = await api('/api/bookmarks');
      bookmarks = data.bookmarks || [];
      renderCards(document.getElementById('navGrid'), bookmarks);
      renderCards(document.getElementById('bookGrid'), bookmarks);
    }

    document.getElementById('add').onclick = async () => {
      const title = document.getElementById('title').value.trim();
      const url = document.getElementById('link').value.trim();
      if (!title || !url) return;
      bookmarks.unshift({ title, url });
      await api('/api/bookmarks', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ bookmarks })
      });
      document.getElementById('title').value = '';
      document.getElementById('link').value = '';
      loadBookmarks();
    };

    async function loadBg() {
      const data = await api('/api/bg');
      document.body.style.backgroundImage = 'url(' + data.url + ')';
      document.getElementById('bgUrl').value = data.mode === 'manual' ? data.url : '';
    }

    document.getElementById('setBg').onclick = async () => {
      const url = document.getElementById('bgUrl').value.trim();
      if (!url) return;
      await api('/api/bg', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode: 'manual', url })
      });
      loadBg();
    };

    document.getElementById('setAuto').onclick = async () => {
      await api('/api/bg', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode: 'auto' })
      });
      loadBg();
    };

    function weatherText(code) {
      if ([0].includes(code)) return '晴';
      if ([1,2,3].includes(code)) return '多云';
      if ([45,48].includes(code)) return '雾';
      if ([51,53,55,61,63,65].includes(code)) return '雨';
      if ([71,73,75,77].includes(code)) return '雪';
      if ([95,96,99].includes(code)) return '雷暴';
      return '未知';
    }

    async function loadWeather() {
      const lat = document.getElementById('lat').value.trim() || '31.23';
      const lon = document.getElementById('lon').value.trim() || '121.47';
      const data = await api('/api/weather?lat=' + encodeURIComponent(lat) + '&lon=' + encodeURIComponent(lon));
      const box = document.getElementById('weatherBox');
      box.innerHTML = '';
      const cur = document.createElement('div');
      cur.className = 'w';
      cur.innerHTML = '<strong>当前</strong><div>' + data.current.temperature_2m + '°C</div><div>' + weatherText(data.current.weathercode) + '</div>';
      box.appendChild(cur);
      data.daily.time.slice(0, 5).forEach((d, i) => {
        const w = document.createElement('div');
        w.className = 'w';
        w.innerHTML = '<strong>' + d.slice(5) + '</strong><div>' + data.daily.temperature_2m_max[i] + ' / ' + data.daily.temperature_2m_min[i] + '°C</div><div>' + weatherText(data.daily.weathercode[i]) + '</div>';
        box.appendChild(w);
      });
    }

    document.getElementById('loadWeather').onclick = loadWeather;
    document.getElementById('logout').onclick = async () => {
      await api('/api/logout', { method: 'POST' });
      location.reload();
    };

    Promise.all([loadBookmarks(), loadBg(), loadWeather()]).catch(console.error);
  </script>
</body>
</html>`;
}
