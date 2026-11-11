import assert from 'node:assert/strict';
import { test } from 'node:test';
import { coverage, hostMatches, parsePattern, pathCoversRoot, policyState } from '../src/match.ts';
import type { AccessApp } from '../src/types.ts';

// Cases taken from Cloudflare's "Application paths" documentation.
test('a subdomain wildcard covers exactly one level', () => {
  assert.equal(hostMatches('*.example.com', 'alpha.example.com'), true);
  assert.equal(hostMatches('*.example.com', 'example.com'), false);
  assert.equal(hostMatches('*.example.com', 'foo.bar.example.com'), false);
  assert.equal(hostMatches('*.test.example.com', 'alpha.test.example.com'), true);
  assert.equal(hostMatches('*.test.example.com', 'test.example.com'), false);
});

test('a wildcard inside a label stays inside that label', () => {
  assert.equal(hostMatches('*test.example.com', 'test.example.com'), true);
  assert.equal(hostMatches('*test.example.com', 'alphatest.example.com'), true);
  assert.equal(hostMatches('*test.example.com', 'beta.test.example.com'), false);
});

test('hostname matching ignores case and treats dots literally', () => {
  assert.equal(hostMatches('App.Example.com', 'app.example.COM'), true);
  assert.equal(hostMatches('a.example.com', 'aXexample.com'), false);
});

test('patterns split into host and path', () => {
  assert.deepEqual(parsePattern('https://App.example.com/admin/*'), { host: 'app.example.com', path: 'admin/*' });
  assert.deepEqual(parsePattern('example.com'), { host: 'example.com', path: '' });
});

test('only an empty path or /* covers the site root', () => {
  assert.equal(pathCoversRoot(''), true);
  assert.equal(pathCoversRoot('*'), true);
  assert.equal(pathCoversRoot('alpha/*'), false);
  assert.equal(pathCoversRoot('admin'), false);
});

const app = (id: string, extra: Partial<AccessApp>): AccessApp => ({ id, type: 'self_hosted', ...extra });

test('coverage finds the app for a hostname via domain, self_hosted_domains or destinations', () => {
  const apps = [
    app('a', { domain: 'a.example.com' }),
    app('b', { self_hosted_domains: ['b.example.com'] }),
    app('c', { destinations: [{ type: 'public', uri: 'c.example.com' }, { type: 'private', uri: 'd.example.com' }] }),
  ];
  assert.equal(coverage('a.example.com', apps).root?.id, 'a');
  assert.equal(coverage('b.example.com', apps).root?.id, 'b');
  assert.equal(coverage('c.example.com', apps).root?.id, 'c');
  assert.equal(coverage('d.example.com', apps).root, undefined);
});

test('a path-only app does not protect the hostname', () => {
  const result = coverage('api.example.com', [app('admin', { domain: 'api.example.com/admin' })]);
  assert.equal(result.root, undefined);
  assert.deepEqual(result.paths, ['/admin']);
});

test('the most specific app wins over a wildcard app', () => {
  const apps = [app('wild', { domain: '*.example.com' }), app('exact', { domain: 'git.example.com' })];
  assert.equal(coverage('git.example.com', apps).root?.id, 'exact');
  assert.equal(coverage('other.example.com', apps).root?.id, 'wild');
});

test('bookmarks and SaaS apps do not count as protection', () => {
  const apps = [
    app('bm', { type: 'bookmark', domain: 'nas.example.com' }),
    app('saas', { type: 'saas', domain: 'nas.example.com' }),
  ];
  assert.equal(coverage('nas.example.com', apps).root, undefined);
});

test('policy state spots bypass-everyone and allow-everyone', () => {
  const everyone = [{ everyone: {} }];
  const team = [{ email_domain: { domain: 'example.com' } }];
  assert.equal(policyState(app('x', { policies: [{ decision: 'allow', include: team }] })).kind, 'ok');
  assert.equal(policyState(app('x', { policies: [] })).kind, 'ok');
  assert.equal(policyState(app('x', { policies: [{ decision: 'allow', include: everyone }] })).kind, 'weak');
  assert.equal(policyState(app('x', { policies: [{ decision: 'bypass', include: everyone }] })).kind, 'bypass');
  // "Everyone" narrowed by a require rule is not everyone.
  assert.equal(
    policyState(app('x', { policies: [{ decision: 'allow', include: everyone, require: team }] })).kind,
    'ok',
  );
  // Bypass outranks a sound allow policy on the same app.
  assert.equal(
    policyState(
      app('x', {
        policies: [
          { decision: 'allow', include: team },
          { decision: 'bypass', include: everyone },
        ],
      }),
    ).kind,
    'bypass',
  );
});
