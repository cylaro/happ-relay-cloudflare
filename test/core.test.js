import assert from 'node:assert/strict';
import test from 'node:test';

import {
  hostAllowed,
  identityHeaders,
  listServers,
  matchRoute,
  outboundToUri,
  parseSubscriptionUris,
  resolveTarget,
  uriName,
  validateEnv,
  escapeHtml,
  flagImage,
} from '../src/core.js';

const ENV = {
  HWID: 'UE42LJXu4DbiCaBv',
  USER_AGENT: 'Happ/1.16.0 (iOS 18.3; iPhone 14 Pro)',
  SECRET_PREFIX: 'my-secret-1',
  ALLOWED_HOSTS: '',
  DEVICE_OS: 'iOS',
  VER_OS: '18.3',
  DEVICE_MODEL: 'iPhone 14 Pro',
};

test('validateEnv accepts a complete configuration', () => {
  assert.equal(validateEnv(ENV).ok, true);
});

test('validateEnv works without optional variables', () => {
  const { ALLOWED_HOSTS, DEVICE_OS, VER_OS, DEVICE_MODEL, ...requiredOnly } = ENV;
  assert.equal(validateEnv(requiredOnly).ok, true);
});

test('validateEnv reports invalid or missing required settings without leaking values', () => {
  const result = validateEnv({ HWID: 'short', USER_AGENT: '', SECRET_PREFIX: 'x', ALLOWED_HOSTS: 'a.com, bad host' });
  assert.equal(result.ok, false);
  assert.equal(result.missing.length, 4);
  for (const entry of result.missing) assert.ok(!entry.includes('bad host'));
});

test('identityHeaders always sends x-hwid and user-agent, optional fields only when set', () => {
  const full = identityHeaders(ENV);
  assert.equal(full['x-hwid'], 'UE42LJXu4DbiCaBv');
  assert.equal(full['x-device-os'], 'iOS');
  assert.equal(full['x-ver-os'], '18.3');
  assert.equal(full['x-device-model'], 'iPhone 14 Pro');
  const { DEVICE_OS, VER_OS, DEVICE_MODEL, ...minimalEnv } = ENV;
  const minimal = identityHeaders(minimalEnv);
  assert.deepEqual(Object.keys(minimal).sort(), ['user-agent', 'x-hwid']);
});

test('matchRoute resolves health and subscription paths behind the secret prefix', () => {
  assert.deepEqual(matchRoute('/my-secret-1/health', ENV), { route: 'health' });
  assert.deepEqual(matchRoute('/my-secret-1/s/token-uuid', ENV), { route: 'subscription', tokenPath: 'token-uuid' });
  assert.deepEqual(matchRoute('/my-secret-1/s/a/b/c', ENV), { route: 'subscription', tokenPath: 'a/b/c' });
});

test('matchRoute accepts full https URLs as the token', () => {
  const link = '/my-secret-1/s/https://other-panel.com/sub/token-1';
  assert.deepEqual(matchRoute(link, ENV), {
    route: 'subscription',
    tokenPath: 'https://other-panel.com/sub/token-1',
  });
});

test('matchRoute rejects wrong prefixes, empty tokens and oversized paths', () => {
  assert.equal(matchRoute('/wrong/s/token', ENV).route, 'not-found');
  assert.equal(matchRoute('/my-secret-1/s/', ENV).route, 'not-found');
  assert.equal(matchRoute('/my-secret-1/other', ENV).route, 'not-found');
  assert.equal(matchRoute(`/${'a'.repeat(3000)}`, ENV).route, 'not-found');
});

test('resolveTarget: full https URL is used as-is', () => {
  assert.equal(resolveTarget(ENV, 'https://other.example.com/sub/t'), 'https://other.example.com/sub/t');
});

test('resolveTarget: collapsed and scheme-less URLs are normalized to https', () => {
  assert.equal(resolveTarget(ENV, 'https:/other.example.com/sub/t'), 'https://other.example.com/sub/t');
  assert.equal(resolveTarget(ENV, 'other.example.com/sub/t'), 'https://other.example.com/sub/t');
});

test('resolveTarget: bare tokens are rejected — a full panel URL is required', () => {
  assert.throws(() => resolveTarget(ENV, 't'), /full https panel URL/);
});

test('resolveTarget: rejects http targets and disallowed hosts', () => {
  const strict = { ...ENV, ALLOWED_HOSTS: 'panel.example.com' };
  assert.throws(() => resolveTarget(strict, 'http://other.example.com/sub/t'), /https/i);
  assert.throws(() => resolveTarget(strict, 'https://evil.example.com/sub/t'), /not allowed/);
  assert.equal(
    resolveTarget(strict, 'https://sub.panel.example.com/sub/t'),
    'https://sub.panel.example.com/sub/t',
  );
});

test('resolveTarget: rejects credentials inside the target URL', () => {
  assert.throws(() => resolveTarget(ENV, 'https://user:pass@panel.example.com/sub/t'), /credentials/);
});

test('resolveTarget: happ links get a clear hint', () => {
  assert.throws(() => resolveTarget(ENV, 'happ://crypt5/xyz'), /decrypt it first/);
});

test('hostAllowed: empty allowlist permits everything; subdomains match their root', () => {
  const open = { ALLOWED_HOSTS: '' };
  assert.equal(hostAllowed(open, 'anything.tld'), true);
  const limited = { ALLOWED_HOSTS: 'panel.example.com' };
  assert.equal(hostAllowed(limited, 'panel.example.com'), true);
  assert.equal(hostAllowed(limited, 'sub.panel.example.com'), true);
  assert.equal(hostAllowed(limited, 'example.com'), false);
  assert.equal(hostAllowed(limited, 'evil-panel.example.com'), false);
});

test('matchRoute resolves the list route behind the secret prefix', () => {
  assert.deepEqual(matchRoute('/my-secret-1/l/token-uuid', ENV), { route: 'list', tokenPath: 'token-uuid' });
  assert.deepEqual(matchRoute('/my-secret-1/l/https://panel.com/sub/t', ENV), { route: 'list', tokenPath: 'https://panel.com/sub/t' });
  assert.equal(matchRoute('/my-secret-1/l/', ENV).route, 'not-found');
});

test('parseSubscriptionUris: plain text list', () => {
  const text = 'vless://a-uuid@host:443#Node1\nss://b#Node2\n\nnot-a-uri';
  assert.deepEqual(parseSubscriptionUris(text), ['vless://a-uuid@host:443#Node1', 'ss://b#Node2']);
});

test('parseSubscriptionUris: base64 body is decoded', () => {
  const encoded = Buffer.from('vless://a#One\nvless://b#Two', 'utf8').toString('base64');
  assert.deepEqual(parseSubscriptionUris(encoded), ['vless://a#One', 'vless://b#Two']);
});

const XRAY_CONFIG = JSON.stringify([
  {
    remarks: '🇵🇱 8 | Польша',
    outbounds: [
      {
        tag: 'proxy',
        protocol: 'vless',
        settings: { vnext: [{ address: 'pl11k.example.icu', port: 8825, users: [{ id: 'uuid-1', encryption: 'none', flow: 'xtls-rprx-vision' }] }] },
        streamSettings: { network: 'tcp', security: 'reality', realitySettings: { serverName: 'yahoo.com', fingerprint: 'chrome', publicKey: 'pbk-x', shortId: 'sid-x' } },
      },
      { tag: 'block', protocol: 'blackhole' },
      { tag: 'direct', protocol: 'freedom' },
    ],
  },
  {
    remarks: '🇩🇪 13 | Германия',
    outbounds: [
      {
        tag: 'proxy',
        protocol: 'hysteria',
        settings: { address: 'de4d.example.icu', port: 8825, version: 2 },
        streamSettings: { network: 'hysteria', hysteriaSettings: { version: 2, auth: 'auth-uuid' }, security: 'tls', tlsSettings: { serverName: 'de4d.example.icu' } },
      },
      { tag: 'direct', protocol: 'freedom' },
    ],
  },
]);

test('parseSubscriptionUris: Happ-style Xray config array -> one URI per element, named by remarks', () => {
  const uris = parseSubscriptionUris(XRAY_CONFIG);
  assert.equal(uris.length, 2);
  assert.match(uris[0], /^vless:\/\/uuid-1@pl11k\.example\.icu:8825\?/);
  assert.match(uris[0], /type=tcp/);
  assert.match(uris[0], /encryption=none/);
  assert.match(uris[0], /security=reality/);
  assert.match(uris[0], /sni=yahoo\.com/);
  assert.match(uris[0], /pbk=pbk-x/);
  assert.match(uris[0], /flow=xtls-rprx-vision/);
  assert.equal(uriName(uris[0]), '🇵🇱 8 | Польша');
  // Xray hysteria outbound maps to the standard hysteria2:// scheme.
  assert.match(uris[1], /^hysteria2:\/\/auth-uuid@de4d\.example\.icu:8825\?/);
  assert.match(uris[1], /sni=de4d\.example\.icu/);
  assert.equal(uriName(uris[1]), '🇩🇪 13 | Германия');
});

const TRANSPORT_MATRIX = [
  ['ws',    { wsSettings: { path: '/wspath', headers: { Host: 'h.example.com' } } },          'type=ws&path=%2Fwspath&host=h.example.com'],
  ['grpc',  { grpcSettings: { serviceName: 'svc', authority: 'au', multiMode: true } },       'type=grpc&serviceName=svc&authority=au&mode=multi'],
  ['kcp',   { kcpSettings: { header: { type: 'dtls' }, seed: 's3cret', mtu: 1400, tti: 50 } }, 'type=kcp&headerType=dtls&seed=s3cret&mtu=1400&tti=50'],
  ['httpupgrade', { httpupgradeSettings: { path: '/hu', host: 'h.example.com' } },            'type=httpupgrade&path=%2Fhu&host=h.example.com'],
  ['xhttp', { xhttpSettings: { mode: 'auto', host: 'x.example.com', path: '/plxh' } },        'type=xhttp&path=%2Fplxh&host=x.example.com&mode=auto'],
  ['tcp',   { tcpSettings: { header: { type: 'http', request: { path: ['/p'], headers: { Host: 'h.example.com' } } } } }, 'type=tcp&headerType=http&path=%2Fp&host=h.example.com'],
];

test('streamParams: every Xray transport maps to its documented share-link parameters', () => {
  for (const [network, settings, expected] of TRANSPORT_MATRIX) {
    const uri = outboundToUri({
      protocol: 'vless',
      settings: { vnext: [{ address: 'h.example.com', port: 443, users: [{ id: 'u1', encryption: 'none' }] }] },
      streamSettings: { network, ...settings, security: 'tls', tlsSettings: { serverName: 'sni.example.com' } },
    });
    assert.ok(uri, network);
    const query = uri.slice(uri.indexOf('?'), uri.indexOf('#'));
    for (const pair of expected.split('&')) {
      assert.ok(query.includes(pair), `${network}: query "${query}" lacks "${pair}"`);
    }
    assert.ok(query.includes('security=tls'), `${network}: security=tls missing`);
    assert.ok(query.includes('sni=sni.example.com'), `${network}: sni missing`);
  }
});

test('outboundToUri: reality shortId array takes first value; IPv6 is bracketed; hysteria2 obfs from finalmask', () => {
  const v6 = outboundToUri({
    protocol: 'vless',
    settings: { vnext: [{ address: '2001:db8::1', port: 443, users: [{ id: 'u1', encryption: 'none' }] }] },
    streamSettings: { network: 'tcp', security: 'reality', realitySettings: { serverName: 'sni', shortIds: ['aa', 'bb'], publicKey: 'pbk', fingerprint: 'chrome', spiderX: '/' } },
  });
  assert.ok(v6.includes('@[2001:db8::1]:443'), v6);
  assert.ok(v6.includes('sid=aa'), v6);
  assert.ok(v6.includes('spx=%2F'), v6);

  const hy2 = outboundToUri({
    protocol: 'hysteria2',
    settings: { servers: [{ address: 'hy.example.com', port: 8443 }], password: 'pw' },
    streamSettings: { network: 'tcp', security: 'tls', tlsSettings: { serverName: 'hy.example.com' }, finalmask: { udp: [{ type: 'salamander', settings: { password: 'obfspw' } }] } },
  });
  assert.match(hy2, /^hysteria2:\/\/pw@hy\.example\.com:8443\?/);
  assert.ok(hy2.includes('obfs=salamander'));
  assert.ok(hy2.includes('obfs-password=obfspw'));
});

test('outboundToUri: ss uses SIP002 plain percent-encoded userinfo; vmess keeps v2 JSON fields', () => {
  const ss = outboundToUri({
    protocol: 'ss',
    settings: { servers: [{ address: '1.2.3.4', port: 8388, method: 'aes-128-gcm', password: 'p@ss:word' }] },
  });
  assert.equal(ss, 'ss://aes-128-gcm:p%40ss%3Aword@1.2.3.4:8388#server');

  const vmess = outboundToUri({
    protocol: 'vmess',
    settings: { vnext: [{ address: 'v.example.com', port: 443, users: [{ id: 'vm-id', alterId: 0 }] }] },
    streamSettings: { network: 'ws', security: 'tls', tlsSettings: { serverName: 'v.example.com', fingerprint: 'chrome', alpn: ['h2'] }, wsSettings: { path: '/ws' } },
  }, 'Имя');
  const decoded = JSON.parse(Buffer.from(vmess.slice(8), 'base64').toString('utf8'));
  assert.equal(decoded.add, 'v.example.com');
  assert.equal(decoded.id, 'vm-id');
  assert.equal(decoded.net, 'ws');
  assert.equal(decoded.tls, 'tls');
  assert.equal(decoded.path, '/ws');
  assert.equal(decoded.fp, 'chrome');
  assert.equal(decoded.alpn, 'h2');
  assert.equal(decoded.ps, 'Имя');
  assert.equal(outboundToUri({ protocol: 'freedom', settings: {} }), null);
  assert.equal(outboundToUri({ protocol: 'vless', settings: { vnext: [] } }), null);
});

test('parseSubscriptionUris: loopback placeholder outbounds (127.0.0.1) are skipped', () => {
  const cfg = JSON.stringify([{
    remarks: 'x',
    outbounds: [
      { tag: 'proxy', protocol: 'vless', settings: { vnext: [{ address: '127.0.0.1', port: 5555, users: [{ id: 'u' }] }] } },
      { tag: 'proxy-2', protocol: 'vless', settings: { vnext: [{ address: 'real.example.com', port: 443, users: [{ id: 'u2' }] }] } },
    ],
  }]);
  const uris = parseSubscriptionUris(cfg);
  assert.equal(uris.length, 1);
  assert.match(uris[0], /real\.example\.com/);
});

test('outboundToUri: vmess outbound becomes base64 JSON link; non-server outbound yields null', () => {
  const vmess = outboundToUri({
    protocol: 'vmess',
    settings: { vnext: [{ address: 'v.example.com', port: 443, users: [{ id: 'vm-id', alterId: 0 }] }] },
    streamSettings: { network: 'ws', security: 'tls', tlsSettings: { serverName: 'v.example.com' }, wsSettings: { path: '/ws' } },
  });
  assert.match(vmess, /^vmess:\/\//);
  const decoded = JSON.parse(Buffer.from(vmess.slice(8), 'base64').toString('utf8'));
  assert.equal(decoded.add, 'v.example.com');
  assert.equal(decoded.id, 'vm-id');
  assert.equal(decoded.net, 'ws');
  assert.equal(decoded.tls, 'tls');
  assert.equal(decoded.path, '/ws');
  assert.equal(outboundToUri({ protocol: 'freedom', settings: {} }), null);
  assert.equal(outboundToUri({ protocol: 'vless', settings: { vnext: [] } }), null);
});

test('uriName: decodes fragment, falls back to empty', () => {
  assert.equal(uriName('vless://a@h:443?x=1#%D0%9D%D0%BE%D0%B4%D0%B0%201'), 'Нода 1');
  assert.equal(uriName('vless://a@h:443'), '');
});

test('listServers: names, indexes and order preserved; default name when no fragment', () => {
  const servers = listServers('vless://a#Франкфурт\nvless://b');
  assert.deepEqual(servers, [
    { index: 1, name: 'Франкфурт', uri: 'vless://a#Франкфурт' },
    { index: 2, name: 'Server 2', uri: 'vless://b' },
  ]);
});

test('escapeHtml escapes dangerous characters', () => {
  assert.equal(escapeHtml('<img src=x onerror="alert(1)">&\''), '&lt;img src=x onerror=&quot;alert(1)&quot;&gt;&amp;&#39;');
});

test('flagImage: converts emoji flag to flagcdn URL; empty without flag', () => {
  assert.equal(flagImage('🇵🇱 9 | Польша'), 'https://flagcdn.com/w40/pl.png');
  assert.equal(flagImage('🇦🇹 13 Австрия'), 'https://flagcdn.com/w40/at.png');
  assert.equal(flagImage('Без флага'), '');
});

test('parseSubscriptionUris: JSON entries with identical endpoints are NOT deduplicated (each remark = one server)', () => {
  const cfg = JSON.stringify([
    {
      remarks: '🇷🇺 1 | Белые списки',
      outbounds: [{ tag: 'proxy', protocol: 'vless', settings: { vnext: [{ address: 'same.example.com', port: 443, users: [{ id: 'u' }] }] } }],
    },
    {
      remarks: '🇷🇺 2 | Белые списки',
      outbounds: [{ tag: 'proxy', protocol: 'vless', settings: { vnext: [{ address: 'same.example.com', port: 443, users: [{ id: 'u' }] }] } }],
    },
  ]);
  const uris = parseSubscriptionUris(cfg);
  assert.equal(uris.length, 2);
  assert.equal(uriName(uris[0]), '🇷🇺 1 | Белые списки');
  assert.equal(uriName(uris[1]), '🇷🇺 2 | Белые списки');
});

test('parseSubscriptionUris: plain text duplicates are still collapsed', () => {
  assert.deepEqual(parseSubscriptionUris('vless://a#One\nvless://a#One'), ['vless://a#One']);
});
