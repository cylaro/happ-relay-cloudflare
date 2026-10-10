import {
  matchRoute,
  resolveTarget,
  identityHeaders,
  filterResponseHeaders,
  validateEnv,
  listServers,
  serversHtml,
} from './core.js';

function healthResponse(env) {
  const { ok, missing } = validateEnv(env);
  const body = JSON.stringify(
    ok
      ? { status: 'ok', hint: 'subscription URL: <worker>/SECRET_PREFIX/s/<token-or-panel-url>' }
      : { status: 'misconfigured', missing },
  );
  return new Response(body, { status: ok ? 200 : 500, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const route = matchRoute(url.pathname, env);
    if (request.method !== 'GET' || route.route === 'not-found') return new Response('Not Found', { status: 404 });
    if (route.route === 'health') return healthResponse(env);

    const { ok, missing } = validateEnv(env);
    if (!ok) return new Response(`Configuration error: missing ${missing[0]}`, { status: 500 });

    let target;
    try {
      target = resolveTarget(env, route.tokenPath);
    } catch (e) {
      return new Response(e.message, { status: e.status || 400 });
    }

    const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
    let upstream;
    try {
      upstream = await fetch(target, {
        headers: identityHeaders(env),
        redirect: 'follow',
        signal: AbortSignal.timeout(15000),
      });
    } catch (e) {
      return new Response('upstream timeout or network error', { status: 504 });
    }
    const declaredLength = Number(upstream.headers.get('content-length') || 0);
    if (declaredLength > MAX_RESPONSE_BYTES) {
      return new Response('upstream response too large', { status: 502 });
    }

    if (route.route === 'list') {
      const text = await upstream.text();
      if (!upstream.ok) return new Response(`upstream error: ${upstream.status}`, { status: 502 });
      const servers = listServers(text);
      if (servers.length === 0) return new Response('no proxy URIs found in subscription', { status: 502 });
      return new Response(serversHtml(servers), { headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' } });
    }

    return new Response(upstream.body, { status: upstream.status, headers: filterResponseHeaders(upstream.headers) });
  },
};
