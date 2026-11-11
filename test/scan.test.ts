import assert from 'node:assert/strict';
import { test } from 'node:test';
import { cloudflareSource, createClient, resolveAccountId } from '../src/cloudflare.ts';
import { demoHosts, demoProber, demoPublicHosts, demoSource } from '../src/demo.ts';
import { discoverHosts } from '../src/discover.ts';
import { classify, httpProber, skipProbe } from '../src/probe.ts';
import { renderJson, renderTable } from '../src/report.ts';
import { failing, scan } from '../src/scan.ts';
import type { Finding } from '../src/types.ts';
import { newlyFailing, parseInterval, sendWebhook } from '../src/watch.ts';

const byHost = (findings: Finding[]) => new Map(findings.map((f) => [f.hostname, f]));

test('discovery merges ingress rules with tunnel DNS records', async () => {
  const hosts = await discoverHosts(demoSource);
  const names = hosts.map((h) => h.hostname);
  assert.ok(names.includes('nas.example.com')); // from ingress
  assert.ok(names.includes('git.internal.example.com')); // only in DNS
  assert.ok(!names.includes('www.example.com')); // CNAME to something that is not a tunnel
  assert.equal(names.filter((n) => n === 'grafana.example.com').length, 1); // in both, listed once
  assert.equal(hosts.find((h) => h.hostname === 'old.example.com')?.dangling, true);
});

test('the demo account produces every verdict', async () => {
  const findings = byHost(await scan({ source: demoSource, probe: demoProber, publicHosts: demoPublicHosts }));
  const status = (host: string) => findings.get(host)?.status;
  assert.equal(status('grafana.example.com'), 'protected');
  assert.equal(status('git.internal.example.com'), 'protected'); // wildcard app
  assert.equal(status('nas.example.com'), 'open'); // no app at all
  assert.equal(status('api.example.com'), 'open'); // only /admin is covered
  assert.equal(status('wiki.example.com'), 'open'); // bypass everyone
  assert.equal(status('old.example.com'), 'open'); // dangling record, no app
  assert.equal(status('paperless.example.com'), 'mismatch'); // app exists, still answers
  assert.equal(status('ha.example.com'), 'weak'); // allow everyone
  assert.equal(status('blog.example.com'), 'public'); // allowlisted
  assert.match(findings.get('api.example.com')?.notes.join(' ') ?? '', /only \/admin is behind Access/);
});

test('without probing, the configuration alone still decides', async () => {
  const findings = byHost(await scan({ source: demoSource, probe: skipProbe }));
  assert.equal(findings.get('nas.example.com')?.status, 'open');
  assert.equal(findings.get('grafana.example.com')?.status, 'protected');
  assert.equal(findings.get('paperless.example.com')?.status, 'protected'); // a mismatch needs the probe
  assert.equal(findings.get('blog.example.com')?.status, 'open'); // no allowlist given
});

test('a 403 does not turn an uncovered hostname into a protected one', async () => {
  const findings = byHost(await scan({ source: demoSource, probe: async () => ({ kind: 'blocked', status: 403 }) }));
  assert.equal(findings.get('nas.example.com')?.status, 'open');
  assert.equal(findings.get('grafana.example.com')?.status, 'protected');
});

test('a wildcard route is expanded into the subdomains we know about', async () => {
  const run = (extraHosts: string[], publicHosts: string[] = []) =>
    scan({ source: demoSource, probe: demoProber, extraHosts, publicHosts }).then(byHost);

  const plain = await run([]);
  assert.equal(plain.get('*.apps.example.com')?.status, 'wildcard');
  assert.equal(plain.get('*.apps.example.com')?.tunnel, 'lab');
  assert.equal(plain.get('vault.apps.example.com')?.status, 'protected'); // found through its Access app
  assert.equal(plain.has('notes.apps.example.com'), false);
  assert.ok(!failing([...plain.values()], true).some((f) => f.status === 'wildcard'));

  assert.match(plain.get('*.apps.example.com')?.notes.join(' ') ?? '', /every subdomain without its own Access application is open/);

  // The same route without a wildcard DNS record cannot be reached by arbitrary subdomains.
  const noWildcardDns = byHost(
    await scan({
      source: { ...demoSource, cnames: async () => [] },
      probe: demoProber,
    }),
  );
  assert.equal(noWildcardDns.get('*.apps.example.com')?.status, 'wildcard');
  assert.match(noWildcardDns.get('*.apps.example.com')?.notes.join(' ') ?? '', /no wildcard DNS record/);

  const listed = await run(['Notes.Apps.example.com', 'elsewhere.example.org']);
  assert.equal(listed.get('notes.apps.example.com')?.status, 'open');
  assert.equal(listed.get('notes.apps.example.com')?.tunnel, 'lab'); // inherits the wildcard's tunnel
  assert.match(listed.get('elsewhere.example.org')?.notes.join(' ') ?? '', /no tunnel route/);

  // A wildcard allowlist entry excuses open subdomains but never hides a protected one.
  const allowed = await run(['notes.apps.example.com'], ['*.apps.example.com']);
  assert.equal(allowed.get('notes.apps.example.com')?.status, 'public');
  assert.equal(allowed.get('vault.apps.example.com')?.status, 'protected');
});

test('weak policies only fail in strict mode', async () => {
  const findings = await scan({ source: demoSource, probe: demoProber, publicHosts: demoPublicHosts });
  const hosts = (strict: boolean) => failing(findings, strict).map((f) => f.hostname);
  assert.ok(!hosts(false).includes('ha.example.com'));
  assert.ok(hosts(true).includes('ha.example.com'));
  assert.ok(!hosts(true).includes('blog.example.com'));
});

test('probe classification', () => {
  const login = 'https://team.cloudflareaccess.com/cdn-cgi/access/login/app.example.com?kid=abc';
  assert.equal(classify(302, login).kind, 'gated');
  assert.equal(classify(302, '/cdn-cgi/access/login/x').kind, 'gated');
  assert.equal(classify(302, 'https://app.example.com/login').kind, 'reachable'); // the app's own login
  assert.equal(classify(301, 'https://evil.example/?next=.cloudflareaccess.com').kind, 'reachable');
  assert.equal(classify(403, null).kind, 'blocked');
  assert.equal(classify(200, null).kind, 'reachable');
  assert.equal(classify(530, null).kind, 'reachable');
});

test('the prober skips wildcards and reports network failures', async () => {
  const boom = (async () => {
    throw new Error('getaddrinfo ENOTFOUND');
  }) as unknown as typeof fetch;
  assert.deepEqual(await httpProber(100, boom)('*.example.com'), { kind: 'skipped' });
  assert.deepEqual(await httpProber(100, boom)('a.example.com'), { kind: 'error', message: 'getaddrinfo ENOTFOUND' });
});

test('reports list failures first and render as valid JSON', async () => {
  const findings = await scan({ source: demoSource, probe: demoProber, publicHosts: demoPublicHosts, extraHosts: demoHosts });
  const table = renderTable(findings, false);
  assert.ok(table.indexOf('OPEN') < table.indexOf('PROTECTED'));
  assert.match(table, /12 hostnames: 5 open, 1 mismatch, 1 weak, 1 wildcard, 3 protected, 1 public/);
  assert.ok(!table.includes('\x1b['));
  assert.equal((JSON.parse(renderJson(findings)) as Finding[]).length, 12);
});

// A fake Cloudflare API, to check paging, auth and error handling of the real client.
function fakeApi(routes: Record<string, (page: number) => unknown>, calls: Request[] = []): typeof fetch {
  return (async (input: RequestInfo | URL, init?: RequestInit) => {
    const req = new Request(input, init);
    calls.push(req);
    const url = new URL(req.url);
    const path = url.pathname.replace('/client/v4', '');
    const handler = routes[path];
    if (!handler) {
      return Response.json({ success: false, errors: [{ message: 'not found' }], result: null }, { status: 404 });
    }
    return Response.json(handler(Number(url.searchParams.get('page') ?? '1')));
  }) as typeof fetch;
}

test('the API client pages through results, sends the token and only uses GET', async () => {
  const calls: Request[] = [];
  const tunnels = Array.from({ length: 70 }, (_, i) => ({ id: `t${i}`, name: `tunnel-${i}` }));
  const client = createClient({
    token: 'secret',
    fetch: fakeApi(
      {
        '/accounts/acc/cfd_tunnel': (page) => ({
          success: true,
          result: tunnels.slice((page - 1) * 50, page * 50),
          result_info: { total_pages: 2 },
        }),
        '/accounts/acc/access/apps': () => ({ success: true, result: [{ id: 'app1', domain: 'a.example.com' }] }),
        '/accounts/acc/access/apps/app1/policies': () => ({ success: true, result: [{ decision: 'allow' }] }),
      },
      calls,
    ),
  });
  const source = cloudflareSource(client, 'acc');
  assert.equal((await source.tunnels()).length, 70);
  assert.deepEqual(await source.ingress('missing'), []); // 404 means locally configured
  assert.equal((await source.accessApps())[0]?.policies?.length, 1); // policies fetched when not embedded
  assert.ok(calls.every((c) => c.method === 'GET' && c.headers.get('authorization') === 'Bearer secret'));
});

test('API errors surface with the status and a permissions hint', async () => {
  const denied = (async () =>
    Response.json({ success: false, errors: [{ message: 'Authentication error' }], result: null }, { status: 403 })) as typeof fetch;
  const client = createClient({ token: 'x', fetch: denied });
  await assert.rejects(cloudflareSource(client, 'acc').tunnels(), /403.*Authentication error.*read permissions/);
  await assert.rejects(cloudflareSource(client, 'acc').ingress('t1'), /403/); // only 404 is swallowed
});

test('the account is taken from the token when it sees exactly one', async () => {
  const one = createClient({ token: 'x', fetch: fakeApi({ '/accounts': () => ({ success: true, result: [{ id: 'only', name: 'Me' }] }) }) });
  assert.equal(await resolveAccountId(one), 'only');
  assert.equal(await resolveAccountId(one, 'given'), 'given');
  const two = createClient({
    token: 'x',
    fetch: fakeApi({ '/accounts': () => ({ success: true, result: [{ id: 'a', name: 'A' }, { id: 'b', name: 'B' }] }) }),
  });
  await assert.rejects(resolveAccountId(two), /several accounts/);
  // A narrowly scoped token lists no accounts; the owner of its zones is used instead.
  const viaZones = createClient({
    token: 'x',
    fetch: fakeApi({
      '/accounts': () => ({ success: true, result: [] }),
      '/zones': () => ({
        success: true,
        result: [
          { id: 'z1', account: { id: 'owner', name: 'Me' } },
          { id: 'z2', account: { id: 'owner', name: 'Me' } },
        ],
      }),
    }),
  });
  assert.equal(await resolveAccountId(viaZones), 'owner');
  const nothing = createClient({
    token: 'x',
    fetch: fakeApi({ '/accounts': () => ({ success: true, result: [] }), '/zones': () => ({ success: true, result: [] }) }),
  });
  await assert.rejects(resolveAccountId(nothing), /cannot see any Cloudflare account/);
});

test('watch helpers', async () => {
  assert.equal(parseInterval('30m'), 1_800_000);
  assert.equal(parseInterval('6h'), 21_600_000);
  assert.equal(parseInterval('90'), 90_000);
  assert.throws(() => parseInterval('soon'), /Invalid interval/);
  assert.throws(() => parseInterval('0m'), /longer than zero/);

  const findings = failing(await scan({ source: demoSource, probe: demoProber }), false);
  const fresh = newlyFailing(findings, ['nas.example.com']);
  assert.ok(!fresh.some((f) => f.hostname === 'nas.example.com'));
  assert.ok(fresh.some((f) => f.hostname === 'wiki.example.com'));

  let body = '';
  const ok = (async (_url: RequestInfo | URL, init?: RequestInit) => {
    body = String(init?.body);
    return new Response('ok');
  }) as typeof fetch;
  await sendWebhook('https://hooks.example/x', fresh, ok);
  assert.match((JSON.parse(body) as { text: string }).text, /newly exposed hostname/);
  const down = (async () => new Response('no', { status: 500 })) as typeof fetch;
  await assert.rejects(sendWebhook('https://hooks.example/x', fresh, down), /HTTP 500/);
});
