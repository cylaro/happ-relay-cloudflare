import assert from 'node:assert/strict';
import test from 'node:test';

import {
  hostAllowed,
  identityHeaders,
  matchRoute,
  resolveTarget,
  validateEnv,
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
