/**
 * Worker 入口：路由分发，调用 auth / api / pages 模块。
 */

import { corsHeaders, json, html } from './utils.js';
import { isAuthenticated, handleLogin, handleLogout } from './auth.js';
import { handleBookmarks, handleBackground, handleWeather } from './api.js';
import { loginPage, appPage } from './pages.js';

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
      return handleBookmarks(request, env);
    }

    if (path === '/api/bg') {
      return handleBackground(request, env);
    }

    if (path === '/api/weather' && request.method === 'GET') {
      return handleWeather(url);
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
