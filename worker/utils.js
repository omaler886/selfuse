/**
 * Shared HTTP helpers: CORS headers, JSON/HTML responses, cookie parsing, HMAC signing.
 */

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

/** HMAC-SHA256 签名：用于 session token 生成与校验 */
async function signValue(value, secret) {
  const msg = new TextEncoder().encode(`${value}:${secret}`);
  const hash = await crypto.subtle.digest('SHA-256', msg);
  const bytes = Array.from(new Uint8Array(hash));
  return bytes.map((b) => b.toString(16).padStart(2, '0')).join('');
}

export { corsHeaders, json, html, safeJson, getCookie, signValue };
