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

function b64encode(str) {
  const bytes = new TextEncoder().encode(str);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

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

function firstServer(outbound) {
  const s = outbound?.settings || {};
  return s.vnext?.[0] || s.servers?.[0] || (s.address && s.port ? { address: s.address, port: s.port } : null) || null;
}

const SERVICE_TAGS = new Set(['block', 'direct', 'dns-out', 'api', 'socks']);

function isLoopback(server) {
  const a = String(server?.address || '');
  return a === '127.0.0.1' || a === '::1' || a === 'localhost';
}

/**
 * Pick the primary proxy outbound of one Xray config element (XTLS JSON
 * subscription: each array element is one connection, primary outbound is
 * usually tagged "proxy"; the rest are service outbounds or loopback hops).
 */
function primaryOutbound(config) {
  const obs = (Array.isArray(config?.outbounds) ? config.outbounds : [])
    .filter(o => o && typeof o === 'object' && PROTOCOLS.has(String(o.protocol || '').toLowerCase()) && !SERVICE_TAGS.has(String(o.tag || '').toLowerCase()));
  if (obs.length === 0) return null;
  const real = obs.filter(o => !isLoopback(firstServer(o)));
  if (real.length === 0) return null;
  return real.find(o => o.tag === 'proxy') || real[0];
}

/** Bracket IPv6 literals so they are valid inside a URI authority. */
function hostPart(address) {
  const a = String(address);
  return a.includes(':') ? `[${a}]` : a;
}

const hostOf = h => (Array.isArray(h) ? h.join(',') : String(h));

/** Build the query string from streamSettings per the Xray share-link spec. */
function streamParams(stream) {
  const params = new URLSearchParams();
  let network = String(stream?.network || 'tcp');
  if (network === 'raw') network = 'tcp';
  if (network === 'splithttp') network = 'xhttp';
  params.set('type', network);

  const security = String(stream?.security || '');
  if (security === 'tls' || security === 'reality') {
    // Two config shapes exist: flat (realitySettings.publicKey) and nested
    // (realitySettings.settings.publicKey + shortIds[] arrays, as used by panels).
    const raw = stream?.[security + 'Settings'] || {};
    const conf = raw.settings && typeof raw.settings === 'object' ? { ...raw, ...raw.settings } : raw;
    params.set('security', security);
    const sni = conf.serverName || (Array.isArray(conf.serverNames) ? conf.serverNames[0] : '');
    if (sni) params.set('sni', sni);
    if (conf.fingerprint) params.set('fp', conf.fingerprint);
    if (conf.alpn) params.set('alpn', Array.isArray(conf.alpn) ? conf.alpn.join(',') : conf.alpn);
    if (conf.allowInsecure) params.set('allowInsecure', '1');
    if (security === 'reality') {
      if (conf.publicKey) params.set('pbk', conf.publicKey);
      const sid = Array.isArray(conf.shortIds) ? conf.shortIds[0] : conf.shortId;
      if (sid) params.set('sid', sid);
      if (conf.spiderX) params.set('spx', conf.spiderX);
      if (conf.mldsa65Verify) params.set('pqv', conf.mldsa65Verify);
    } else {
      if (conf.echConfigList) params.set('ech', conf.echConfigList);
      if (conf.verifyPeerCertByName) params.set('vcn', conf.verifyPeerCertByName);
      if (conf.pinnedPeerCertSha256) params.set('pcs', Array.isArray(conf.pinnedPeerCertSha256) ? conf.pinnedPeerCertSha256.join(',') : conf.pinnedPeerCertSha256);
    }
  } else if (security && security !== 'none') {
    params.set('security', security);
  }

  if (network === 'tcp' && stream?.tcpSettings?.header) {
    const header = stream.tcpSettings.header;
    if (header.type && header.type !== 'none') {
      params.set('headerType', header.type);
      if (header.type === 'http' && header.request) {
        if (header.request.path) params.set('path', hostOf(header.request.path));
        const host = header.request.headers?.Host ?? header.request.headers?.host;
        if (host) params.set('host', hostOf(host));
      }
    }
  } else if (network === 'ws' && stream?.wsSettings) {
    if (stream.wsSettings.path) params.set('path', stream.wsSettings.path);
    const host = stream.wsSettings.host ?? stream.wsSettings.headers?.Host ?? stream.wsSettings.headers?.host;
    if (host) params.set('host', hostOf(host));
  } else if (network === 'httpupgrade' && stream?.httpupgradeSettings) {
    if (stream.httpupgradeSettings.path) params.set('path', stream.httpupgradeSettings.path);
    const host = stream.httpupgradeSettings.host ?? stream.httpupgradeSettings.headers?.Host;
    if (host) params.set('host', hostOf(host));
  } else if (network === 'grpc' && stream?.grpcSettings) {
    if (stream.grpcSettings.serviceName) params.set('serviceName', stream.grpcSettings.serviceName);
    if (stream.grpcSettings.authority) params.set('authority', stream.grpcSettings.authority);
    if (stream.grpcSettings.multiMode) params.set('mode', 'multi');
    if (stream.grpcSettings.userAgent) params.set('userAgent', stream.grpcSettings.userAgent);
  } else if (network === 'kcp' && stream?.kcpSettings) {
    const kcp = stream.kcpSettings;
    if (kcp.header?.type && kcp.header.type !== 'none') params.set('headerType', kcp.header.type);
    if (kcp.seed) params.set('seed', kcp.seed);
    if (kcp.mtu) params.set('mtu', String(kcp.mtu));
    if (kcp.tti) params.set('tti', String(kcp.tti));
  } else if (network === 'xhttp' && stream?.xhttpSettings) {
    const x = stream.xhttpSettings;
    if (x.path) params.set('path', x.path);
    if (x.host) params.set('host', x.host);
    if (x.mode) params.set('mode', x.mode);
    if (x.extra && typeof x.extra === 'object') params.set('extra', JSON.stringify(x.extra));
  } else if (network === 'quic' && stream?.quicSettings) {
    const q = stream.quicSettings;
    if (q.security) params.set('quicSecurity', q.security);
    if (q.key) params.set('key', q.key);
    if (q.header?.type) params.set('headerType', q.header.type);
  } else if (network === 'hysteria' && stream?.hysteriaSettings) {
    if (stream.hysteriaSettings.version) params.set('version', String(stream.hysteriaSettings.version));
  }
  return params;
}

/** Hysteria2 obfs params from xray finalmask (salamander/gecko). */
function finalmaskParams(stream, params) {
  const masks = stream?.finalmask?.udp;
  if (!Array.isArray(masks)) return;
  for (const m of masks) {
    if (m?.type === 'salamander' || m?.type === 'gecko') {
      params.set('obfs', m.type);
      if (m.settings?.password) params.set('obfs-password', m.settings.password);
      break;
    }
  }
}

/** Convert one Xray/V2Ray outbound into a shareable proxy URI, or null if not representable. */
export function outboundToUri(outbound, remark = '') {
  const protocol = String(outbound?.protocol || '').toLowerCase();
  const server = firstServer(outbound);
  if (!server || !server.address || !server.port) return null;
  const name = encodeURIComponent(String(remark || outbound.tag || '').replace(/[\r\n\t#?/&]/g, ' ').trim() || 'server');
  const addr = hostPart(server.address);
  const params = streamParams(outbound.streamSettings);
  const user = server.users?.[0] || {};
  const security = String(outbound.streamSettings?.security || '');

  if (protocol === 'vless' && user.id) {
    params.set('encryption', user.encryption || 'none');
    if (user.flow) params.set('flow', user.flow);
    return `vless://${encodeURIComponent(user.id)}@${addr}:${server.port}?${params}#${name}`;
  }
  if (protocol === 'vmess' && user.id) {
    const network = String(outbound.streamSettings?.network || 'tcp').replace('raw', 'tcp');
    const vm = {
      v: '2', ps: String(remark || outbound.tag || 'server'), add: String(server.address), port: String(server.port), id: user.id,
      aid: String(user.alterId ?? 0), scy: user.security || 'auto',
      net: network, type: outbound.streamSettings?.kcpSettings?.header?.type || 'none',
      host: params.get('host') || '', path: params.get('path') || '',
      tls: security === 'tls' ? 'tls' : security === 'reality' ? 'reality' : '',
      sni: params.get('sni') || '', fp: params.get('fp') || '', alpn: params.get('alpn') || '',
    };
    return `vmess://${b64encode(JSON.stringify(vm))}`;
  }
  if (protocol === 'trojan' && server.password) {
    if (security === '') params.set('security', 'none');
    return `trojan://${encodeURIComponent(server.password)}@${addr}:${server.port}?${params}#${name}`;
  }
  if (protocol === 'ss' && server.method && server.password) {
    // SIP002: plain userinfo (method:password percent-encoded) is valid for every cipher,
    // unlike websafe-base64 which is forbidden for AEAD-2022.
    const userinfo = `${encodeURIComponent(server.method)}:${encodeURIComponent(server.password)}`;
    return `ss://${userinfo}@${addr}:${server.port}#${name}`;
  }
  if (protocol === 'socks') {
    const u = user.user ? `${encodeURIComponent(user.user)}:${encodeURIComponent(user.pass || '')}@` : '';
    return `socks://${u}${addr}:${server.port}#${name}`;
  }
  if (protocol === 'hysteria2' || protocol === 'hy2') {
    const auth = outbound.settings?.password || server.password || user.id || '';
    finalmaskParams(outbound.streamSettings, params);
    const authPart = auth ? `${encodeURIComponent(auth)}@` : '';
    return `hysteria2://${authPart}${addr}:${server.port}?${params}#${name}`;
  }
  if (protocol === 'hysteria') {
    // Xray's hysteria outbound is Hysteria2-compatible (auth + TLS + optional obfs).
    const auth = outbound.streamSettings?.hysteriaSettings?.auth || server.password || outbound.settings?.password || outbound.settings?.auth_str || '';
    finalmaskParams(outbound.streamSettings, params);
    if (params.get('security') === 'tls') params.delete('security');
    params.delete('type');
    const authPart = auth ? `${encodeURIComponent(auth)}@` : '';
    return `hysteria2://${authPart}${addr}:${server.port}?${params}#${name}`;
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
  const configs = Array.isArray(parsed) ? parsed : [parsed];
  const uris = [];
  for (const config of configs) {
    if (!config || typeof config !== 'object' || !Array.isArray(config.outbounds)) continue;
    const remark = String(config.remarks || '').replace(/[\r\n#?]/g, ' ').trim();
    const outbound = primaryOutbound(config);
    if (!outbound) continue;
    const uri = outboundToUri(outbound, remark);
    if (uri) uris.push(uri);
  }
  return uris;
}

/**
 * Extract proxy URIs (vless://, vmess://, ss://, …) from a subscription body:
 * Xray/V2Ray JSON config, plain text, base64 text, or a mix. Order is preserved.
 * Each JSON config element is one server entry (like in Happ) — no deduplication,
 * because different entries may intentionally share the same endpoint.
 */
export function parseSubscriptionUris(text) {
  const fromJson = parseJsonSubscription(text);
  if (fromJson.length > 0) return fromJson;
  const body = decodeIfBase64(String(text || '').trim());
  if (!body) return [];
  const seen = new Set();
  return body.split(/\r?\n/).map(l => l.trim()).filter(l => URI_LINE_RE.test(l) && !seen.has(l) && seen.add(l));
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

/**
 * Regional-indicator emoji flag ("🇵🇱") -> image URL with the same flag.
 * Falls back to an empty string when the name has no flag.
 */
export function flagImage(name) {
  const m = String(name).match(/[\u{1F1E6}-\u{1F1FF}][\u{1F1E6}-\u{1F1FF}]/u);
  if (!m) return '';
  const code = [...m[0]].map(c => String.fromCharCode(c.codePointAt(0) - 0x1F1E6 + 65)).join('');
  return `https://flagcdn.com/w40/${code.toLowerCase()}.png`;
}

/** Minimal HTML page listing every server with its name and copyable link. */
export function serversHtml(servers) {
  const cards = servers.map(s => {
    const flag = flagImage(s.name);
    const flagHtml = flag ? `<img class="flag" src="${flag}" alt="" width="24" height="18">` : '';
    return `
  <section class="card">
    <h2>${flagHtml}<span class="num">${escapeHtml(s.index)}.</span> ${escapeHtml(s.name)}</h2>
    <code>${escapeHtml(s.uri)}</code>
    <div class="actions">
      <a href="${escapeHtml(s.uri)}">Подключить</a>
      <a href="${escapeHtml(s.uri)}" class="copy" data-uri="${escapeHtml(s.uri)}">Копировать</a>
    </div>
  </section>`;
  }).join('\n');
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
  h2 { font-size: 1rem; margin: 0 0 0.6rem; word-break: break-word; display: flex; align-items: center; gap: 0.5rem; }
  .flag { border-radius: 3px; flex: none; }
  .num { color: #8b97a5; }
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
