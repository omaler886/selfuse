/**
 * API 处理器：书签 CRUD、背景图管理、天气代理。
 */

import { json, safeJson } from './utils.js';

const defaultBookmarks = [
  { title: 'Cloudflare', url: 'https://dash.cloudflare.com/' },
  { title: 'GitHub', url: 'https://github.com/' },
  { title: 'OpenAI', url: 'https://platform.openai.com/' }
];

/** GET/POST /api/bookmarks */
async function handleBookmarks(request, env) {
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
  return json({ error: 'Method not allowed' }, 405);
}

/** GET/POST /api/bg */
async function handleBackground(request, env) {
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
  return json({ error: 'Method not allowed' }, 405);
}

/** GET /api/weather */
async function handleWeather(url) {
  const lat = Number(url.searchParams.get('lat') || '31.23');
  const lon = Number(url.searchParams.get('lon') || '121.47');
  const weatherRes = await fetch(
    `https://api.open-meteo.com/v1/forecast?latitude=${lat}&longitude=${lon}&daily=weathercode,temperature_2m_max,temperature_2m_min&current=temperature_2m,weathercode&timezone=auto`
  );
  if (!weatherRes.ok) {
    return json({ error: '天气服务不可用' }, 502);
  }
  const data = await weatherRes.json();
  return json(data);
}

/** 获取背景图：手动优先，否则每日自动生成 */
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

export { defaultBookmarks, handleBookmarks, handleBackground, handleWeather };
