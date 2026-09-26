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

/**
 * Route a request path:
 *   /<prefix>/health        -> { route: 'health' }
 *   /<prefix>/s/<token...>  -> { route: 'subscription', tokenPath }
 *   anything else           -> { route: 'not-found' }
 *
 * tokenPath may be a bare subscription token (resolved against PANEL_BASE)
 * or a full https:// URL of any allowed panel.
 */
export function matchRoute(pathname, env) {
  const prefix = normalizedPrefix(env);
  if (prefix === '/' || pathname.length > 2048) return { route: 'not-found' };
  if (pathname === `${prefix}/health`) return { route: 'health' };
  const subscriptionPrefix = `${prefix}/s/`;
  if (pathname.startsWith(subscriptionPrefix) && pathname.length > subscriptionPrefix.length) {
    const tokenPath = pathname.slice(subscriptionPrefix.length).replace(/^\/+/, '');
    if (tokenPath && !/\s/.test(tokenPath)) return { route: 'subscription', tokenPath };
  }
  return { route: 'not-found' };
}

/**
 * Resolve the token path to an upstream URL.
 * The token path must be a full https URL of the panel subscription endpoint;
 * the host must pass ALLOWED_HOSTS if the allowlist is set.
 */
export function resolveTarget(env, tokenPath) {
  const raw = String(tokenPath || '').replace(/^\/+/, '');
  if (!/^https:\/\//i.test(raw)) throw err('token must be a full https panel URL');

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
