/**
 * 认证模块：登录、登出、session 校验。
 * 依赖 utils.js 的 json / safeJson / getCookie / signValue。
 */

import { json, safeJson, getCookie, signValue } from './utils.js';

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

export { isAuthenticated, handleLogin, handleLogout };
