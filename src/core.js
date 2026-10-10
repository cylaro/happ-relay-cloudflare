/**
 * Pure relay logic — no Cloudflare-specific APIs, unit-testable in Node.
 */

const RESPONSE_HEADER_ALLOWLIST = [
  'content-type',
  'subscription-userinfo',
  'profile-title',
  'profile-update-interval',
  'profile-web-page-url',
  'support-url',
  'x-hwid-active',
  'x-hwid-not-supported',
  'x-hwid-max-devices-reached',
  'x-hwid-limit',
];

const HWID_PATTERN = /^[A-Za-z0-9=-]{10,64}$/;

const err = (message, status = 400) => Object.assign(new Error(message), { status });

/** Check worker configuration. Returns { ok, missing } without leaking values. */
export function validateEnv(env) {
  const missing = [];
  if (!HWID_PATTERN.test(String(env?.HWID || ''))) missing.push('HWID (10-64 chars: A-Z a-z 0-9 = -)');
  if (!env?.USER_AGENT) missing.push('USER_AGENT');
  if (!/^[A-Za-z0-9_-]{8,}$/.test(String(env?.SECRET_PREFIX || ''))) missing.push('SECRET_PREFIX (8+ chars: A-Z a-z 0-9 _ -)');
  const hosts = String(env?.ALLOWED_HOSTS || '');
  if (hosts.split(',').some(h => h.trim() && !/^[a-z0-9.-]+$/i.test(h.trim()))) missing.push('ALLOWED_HOSTS (comma-separated hostnames)');
  return { ok: missing.length === 0, missing };
}

/** Identity headers presented to the panel. */
export function identityHeaders(env) {
  const headers = {
    'x-hwid': env.HWID,
    'user-agent': env.USER_AGENT,
  };
  if (env.DEVICE_OS) headers['x-device-os'] = env.DEVICE_OS;
  if (env.VER_OS) headers['x-ver-os'] = env.VER_OS;
  if (env.DEVICE_MODEL) headers['x-device-model'] = env.DEVICE_MODEL;
  return headers;
}

export function parseAllowedHosts(env) {
  return String(env?.ALLOWED_HOSTS || '')
    .split(',')
    .map(h => h.trim().toLowerCase())
    .filter(Boolean);
}

/** Empty ALLOWED_HOSTS means every https host is allowed. */
export function hostAllowed(env, hostname) {
  const hosts = parseAllowedHosts(env);
  if (hosts.length === 0) return true;
  const host = String(hostname || '').toLowerCase();
  return hosts.some(h => host === h || host.endsWith('.' + h));
}

function normalizedPrefix(env) {
  return '/' + String(env?.SECRET_PREFIX || '').replace(/^\/+|\/+$/g, '');
}

/** Length-safe constant-time string comparison (length itself is public — it is in the URL). */
export function safeEqual(a, b) {
  const A = new TextEncoder().encode(String(a));
  const B = new TextEncoder().encode(String(b));
  if (A.length !== B.length) return false;
  let diff = 0;
  for (let i = 0; i < A.length; i++) diff |= A[i] ^ B[i];
  return diff === 0;
}

/**
 * Route a request path:
 *   /<prefix>/health        -> { route: 'health' }
 *   /<prefix>/s/<token...>  -> { route: 'subscription', tokenPath }
 *   /<prefix>/l/<token...>  -> { route: 'list', tokenPath }
 *   anything else           -> { route: 'not-found' }
 *
 * tokenPath may be a bare subscription token (resolved against PANEL_BASE)
 * or a full https:// URL of any allowed panel.
 */
export function matchRoute(pathname, env) {
  const prefix = normalizedPrefix(env);
  if (prefix === '/' || pathname.length > 2048 || !env?.SECRET_PREFIX) return { route: 'not-found' };
  if (safeEqual(pathname, `${prefix}/health`)) return { route: 'health' };
  for (const [route, seg] of [['subscription', 's'], ['list', 'l']]) {
    const routePrefix = `${prefix}/${seg}/`;
    if (safeEqual(pathname.slice(0, routePrefix.length), routePrefix) && pathname.length > routePrefix.length) {
      const tokenPath = pathname.slice(routePrefix.length).replace(/^\/+/, '');
      if (tokenPath && !/\s/.test(tokenPath)) return { route, tokenPath };
    }
  }
  return { route: 'not-found' };
}

/**
 * Resolve the token path to an upstream URL.
 * The token path points to the panel subscription endpoint:
 *   full https URL (single or doubled slashes are tolerated)
 *   or scheme-less host/path (https:// is assumed)
 * The host must pass ALLOWED_HOSTS if the allowlist is set.
 */
export function resolveTarget(env, tokenPath) {
  let raw = String(tokenPath || '').trim().replace(/^\/+/, '');
  // Apps and CDNs sometimes collapse "https://" into "https:/": restore it.
  raw = raw.replace(/^(https?):\/{1,}/i, '$1://');
  if (/^happ:\/\//i.test(raw)) throw err('this is an encrypted happ link — decrypt it first');
  if (!/^https:\/\//i.test(raw)) {
    // Scheme-less host/path: assume https.
    if (/^[a-z0-9.-]+\.[a-z]{2,}([/?#]|$)/i.test(raw)) raw = 'https://' + raw;
    else throw err('token must be a full https panel URL');
  }

  let url;
  try {
    url = new URL(raw);
  } catch {
    throw err('invalid target URL');
  }
  if (url.protocol !== 'https:') throw err('only https targets are allowed');
  if (url.username || url.password) throw err('credentials in target URL are not allowed');
  if (!hostAllowed(env, url.hostname)) throw err('target host is not allowed', 403);
  return url.href;
}

/**
 * Copy only panel-relevant response headers (traffic quota, profile metadata,
 * HWID feedback). Everything else — including set-cookie — is dropped.
 */
export function filterResponseHeaders(upstreamHeaders) {
  const headers = new Headers();
  for (const name of RESPONSE_HEADER_ALLOWLIST) {
    const value = upstreamHeaders.get(name);
    if (value) headers.set(name, value);
  }
  headers.set('cache-control', 'no-store');
  return headers;
}

const URI_LINE_RE = /^(?:vless|vmess|ss|socks|trojan|hysteria2|hy2|hysteria):\/\//i;
const PROTOCOLS = new Set(['vless', 'vmess', 'trojan', 'ss', 'socks', 'hysteria', 'hysteria2', 'hy2']);

/** Decode a base64 subscription body if it does not already look like plain URIs. */
function decodeIfBase64(text) {
  if (URI_LINE_RE.test(text)) return text;
  try {
    const binary = atob(text.replace(/\s+/g, ''));
    const bytes = Uint8Array.from(binary, c => c.charCodeAt(0));
    return new TextDecoder('utf-8').decode(bytes);
  } catch {
    return text;
  }
}

/** Recursively collect every outbounds[] entry from parsed JSON (Xray/V2Ray config, possibly wrapped). */
function collectOutbounds(node, acc) {
  if (!node || typeof node !== 'object') return acc;
  if (Array.isArray(node)) {
    for (const item of node) collectOutbounds(item, acc);
    return acc;
  }
  if (Array.isArray(node.outbounds)) {
    for (const o of node.outbounds) if (o && typeof o === 'object' && PROTOCOLS.has(String(o.protocol || '').toLowerCase())) acc.push(o);
  }
  for (const v of Object.values(node)) collectOutbounds(v, acc);
  return acc;
}

function firstServer(outbound) {
  const s = outbound?.settings || {};
  return s.vnext?.[0] || s.servers?.[0] || null;
}

/** Build query params from streamSettings (security, transport, reality/tls details). */
function streamParams(stream) {
  const params = new URLSearchParams();
  const network = String(stream?.network || 'tcp');
  params.set('type', network);
  const security = String(stream?.security || '');
  if (security === 'tls' || security === 'reality') {
    const conf = stream?.[security + 'Settings'] || {};
    params.set('security', security);
    if (conf.serverName) params.set('sni', conf.serverName);
    if (conf.fingerprint) params.set('fp', conf.fingerprint);
    if (conf.alpn) params.set('alpn', Array.isArray(conf.alpn) ? conf.alpn.join(',') : conf.alpn);
    if (conf.publicKey) params.set('pbk', conf.publicKey);
    if (conf.shortId) params.set('sid', conf.shortId);
    if (conf.spiderX) params.set('spx', conf.spiderX);
    if (conf.allowInsecure) params.set('allowInsecure', '1');
  }
  const hostOf = h => (Array.isArray(h) ? h.join(',') : String(h));
  if (network === 'ws' && stream?.wsSettings) {
    if (stream.wsSettings.path) params.set('path', stream.wsSettings.path);
    if (stream.wsSettings.headers?.Host) params.set('host', hostOf(stream.wsSettings.headers.Host));
  }
  if (network === 'grpc' && stream?.grpcSettings?.serviceName) params.set('serviceName', stream.grpcSettings.serviceName);
  if (network === 'tcp' && stream?.tcpSettings?.header?.request?.headers?.Host) params.set('host', hostOf(stream.tcpSettings.header.request.headers.Host));
  if (network === 'http' && stream?.tcpSettings?.header?.request?.path) params.set('path', hostOf(stream.tcpSettings.header.request.path));
  return params;
}

/** Convert one Xray/V2Ray outbound into a shareable proxy URI, or null if not representable. */
export function outboundToUri(outbound) {
  const protocol = String(outbound?.protocol || '').toLowerCase();
  const server = firstServer(outbound);
  if (!server || !server.address || !server.port) return null;
  const tag = String(outbound.tag || '').replace(/[\r\n\t#?/&]/g, ' ').trim() || 'server';
  const name = encodeURIComponent(tag);
  const addr = String(server.address);
  const port = Number(server.port);
  const params = streamParams(outbound.streamSettings);
  const user = server.users?.[0] || {};

  if (protocol === 'vless' && user.id) {
    if (user.encryption && user.encryption !== 'none') params.set('encryption', user.encryption);
    if (user.flow) params.set('flow', user.flow);
    return `vless://${encodeURIComponent(user.id)}@${addr}:${port}?${params}#${name}`;
  }
  if (protocol === 'vmess' && user.id) {
    const vm = {
      v: '2', ps: tag, add: addr, port: String(port), id: user.id,
      aid: String(user.alterId ?? 0), scy: user.security || 'auto',
      net: String(outbound.streamSettings?.network || 'tcp'), type: 'none',
      host: params.get('host') || '', path: params.get('path') || '',
      tls: params.get('security') === 'tls' ? 'tls' : '',
      sni: params.get('sni') || '', fp: params.get('fp') || '',
    };
    return `vmess://${btoa(JSON.stringify(vm))}`;
  }
  if (protocol === 'trojan' && server.password) {
    return `trojan://${encodeURIComponent(server.password)}@${addr}:${port}?${params}#${name}`;
  }
  if (protocol === 'ss' && server.method && server.password) {
    return `ss://${btoa(`${server.method}:${server.password}`)}@${addr}:${port}#${name}`;
  }
  if (protocol === 'socks') {
    const u = user.user ? `${encodeURIComponent(user.user)}:${encodeURIComponent(user.pass || '')}@` : '';
    return `socks://${u}${addr}:${port}#${name}`;
  }
  if ((protocol === 'hysteria2' || protocol === 'hy2')) {
    const pass = encodeURIComponent(outbound.settings?.password || server.password || '');
    return `hysteria2://${pass ? pass + '@' : ''}${addr}:${port}?${params}#${name}`;
  }
  if (protocol === 'hysteria') {
    const auth = server.password || outbound.settings?.auth_str || '';
    if (auth) params.set('auth', auth);
    return `hysteria://${addr}:${port}?${params}#${name}`;
  }
  return null;
}

/** Parse a JSON/Xray subscription body into proxy URIs. Returns [] when the body is not JSON. */
export function parseJsonSubscription(text) {
  const trimmed = String(text || '').trim();
  if (!trimmed.startsWith('{') && !trimmed.startsWith('[')) return [];
  let parsed;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    const start = trimmed.indexOf('{');
    const end = trimmed.lastIndexOf('}');
    if (start === -1 || end <= start) return [];
    try {
      parsed = JSON.parse(trimmed.slice(start, end + 1));
    } catch {
      return [];
    }
  }
  return collectOutbounds(parsed, []).map(outboundToUri).filter(Boolean);
}

/**
 * Extract proxy URIs (vless://, vmess://, ss://, …) from a subscription body:
 * Xray/V2Ray JSON config, plain text, base64 text, or a mix. Order is preserved.
 * Duplicate servers (same protocol, address, port and identity — configs often
 * embed the same set twice) are kept once, first occurrence wins.
 */
export function parseSubscriptionUris(text) {
  const fromJson = parseJsonSubscription(text);
  if (fromJson.length > 0) {
    const seen = new Set();
    return fromJson.filter(uri => {
      const key = uri.replace(/#.*$/, '');
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }
  const body = decodeIfBase64(String(text || '').trim());
  if (!body) return [];
  return body.split(/\r?\n/).map(l => l.trim()).filter(URI_LINE_RE.test.bind(URI_LINE_RE));
}

/** Human-readable name from a proxy URI fragment (#Node), decoded and sanitized. */
export function uriName(uri) {
  const m = String(uri).match(/#([^#?]*)$/);
  if (!m) return '';
  try {
    return decodeURIComponent(m[1]).replace(/[\r\n\t<>&"]/g, ' ').trim();
  } catch {
    return m[1].replace(/[\r\n\t<>&"]/g, ' ').trim();
  }
}

/** Escape a string for safe interpolation into HTML text/attributes. */
export function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
}

/** One entry per server: index (1-based), display name, proxy URI. */
export function listServers(text) {
  return parseSubscriptionUris(text).map((uri, i) => ({
    index: i + 1,
    name: uriName(uri) || `Server ${i + 1}`,
    uri,
  }));
}

/** Minimal HTML page listing every server with its name and copyable link. */
export function serversHtml(servers) {
  const cards = servers.map(s => `
  <section class="card">
    <h2>${escapeHtml(s.index)}. ${escapeHtml(s.name)}</h2>
    <code>${escapeHtml(s.uri)}</code>
    <div class="actions">
      <a href="${escapeHtml(s.uri)}">Подключить</a>
      <a href="${escapeHtml(s.uri)}" class="copy" data-uri="${escapeHtml(s.uri)}">Копировать</a>
    </div>
  </section>`).join('\n');
  return `<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Серверы подписки (${servers.length})</title>
<style>
  :root { color-scheme: dark; }
  body { font-family: system-ui, sans-serif; background: #12161d; color: #dde3ea; margin: 0 auto; padding: 1rem; max-width: 46rem; }
  h1 { font-size: 1.2rem; }
  .card { background: #1a2028; border: 1px solid #2a3340; border-radius: 10px; padding: 0.9rem 1rem; margin: 0.8rem 0; }
  h2 { font-size: 1rem; margin: 0 0 0.6rem; word-break: break-word; }
  code { display: block; font-size: 0.78rem; color: #9fb0c3; background: #12161d; border-radius: 6px; padding: 0.6rem; overflow-wrap: anywhere; }
  .actions { display: flex; gap: 0.8rem; margin-top: 0.6rem; }
  a { color: #6db3f2; }
  a.copy { cursor: pointer; }
</style>
</head>
<body>
<h1>Серверы подписки (${servers.length})</h1>
${cards}
<script>
document.querySelectorAll('a.copy').forEach(a => a.addEventListener('click', e => {
  e.preventDefault();
  navigator.clipboard.writeText(a.dataset.uri).then(() => {
    const t = a.textContent; a.textContent = 'Скопировано';
    setTimeout(() => { a.textContent = t; }, 1200);
  });
}));
</script>
</body>
</html>`;
}
