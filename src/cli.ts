#!/usr/bin/env node
import { readFile } from 'node:fs/promises';
import { setTimeout as sleep } from 'node:timers/promises';
import { parseArgs } from 'node:util';
import { cloudflareSource, createClient, resolveAccountId } from './cloudflare.ts';
import { demoHosts, demoProber, demoPublicHosts, demoSource } from './demo.ts';
import { httpProber, skipProbe } from './probe.ts';
import { renderJson, renderTable } from './report.ts';
import { failing, scan, type ScanOptions } from './scan.ts';
import { newlyFailing, parseInterval, readState, sendWebhook, writeState } from './watch.ts';

const HELP = `tunnelcheck - find Cloudflare Tunnel hostnames that are open without a login

Usage:
  tunnelcheck scan  [options]     scan once and print a report
  tunnelcheck watch [options]     scan on a schedule and alert on new findings

Options:
  --json               print JSON instead of a table
  --strict             also fail on "weak" (allow-everyone) policies
  --no-probe           only read the configuration, send no requests to the hostnames
  --public <host>      hostname that is meant to be public (repeatable, wildcards allowed)
  --host <host>        extra hostname to check, e.g. a subdomain behind a wildcard route (repeatable)
  --config <file>      JSON config file (default: tunnelcheck.json if present)
  --timeout <ms>       probe timeout per hostname (default: 10000)
  --demo               use a built-in fake account instead of Cloudflare
  --interval <time>    watch: time between scans, e.g. 30m, 6h, 1d (default: 6h)
  --webhook <url>      watch: POST an alert here (or set TUNNELCHECK_WEBHOOK_URL)
  --state <file>       watch: where to remember findings (default: .tunnelcheck-state.json)
  -h, --help           show this help

Environment:
  CLOUDFLARE_API_TOKEN     read-only API token (required unless --demo)
  CLOUDFLARE_ACCOUNT_ID    account to scan (optional if the token sees one account)

Exit codes: 0 nothing exposed, 1 exposed hostnames found, 2 the scan could not run.`;

const HOSTNAME = /^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z][a-z0-9-]{1,62}$/i;

interface Config {
  public?: string[];
  hosts?: string[];
}

async function loadConfig(path: string | undefined): Promise<Config> {
  try {
    const parsed: unknown = JSON.parse(await readFile(path ?? 'tunnelcheck.json', 'utf8'));
    if (typeof parsed !== 'object' || parsed === null) throw new Error('the config must be a JSON object');
    for (const key of ['public', 'hosts'] as const) {
      const list = (parsed as Config)[key];
      if (list !== undefined && !(Array.isArray(list) && list.every((x) => typeof x === 'string'))) {
        throw new Error(`"${key}" must be a list of hostnames`);
      }
    }
    return parsed as Config;
  } catch (err) {
    // A missing default config is fine; a missing file the user named is not.
    if (path === undefined && (err as NodeJS.ErrnoException).code === 'ENOENT') return {};
    throw new Error(`Cannot read config ${path ?? 'tunnelcheck.json'}: ${(err as Error).message}`);
  }
}

async function main(): Promise<number> {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      json: { type: 'boolean', default: false },
      strict: { type: 'boolean', default: false },
      'no-probe': { type: 'boolean', default: false },
      public: { type: 'string', multiple: true, default: [] },
      host: { type: 'string', multiple: true, default: [] },
      config: { type: 'string' },
      timeout: { type: 'string', default: '10000' },
      demo: { type: 'boolean', default: false },
      interval: { type: 'string', default: '6h' },
      webhook: { type: 'string' },
      state: { type: 'string', default: '.tunnelcheck-state.json' },
      help: { type: 'boolean', short: 'h', default: false },
    },
  });

  const command = positionals[0];
  if (values.help || command === undefined) {
    console.log(HELP);
    return values.help ? 0 : 2;
  }
  if (command !== 'scan' && command !== 'watch') {
    throw new Error(`Unknown command "${command}". Run tunnelcheck --help.`);
  }

  const timeout = Number(values.timeout);
  if (!Number.isFinite(timeout) || timeout <= 0) throw new Error('--timeout must be a positive number of ms.');

  const config = await loadConfig(values.config);
  let options: ScanOptions;
  // These end up in a URL that gets requested, so accept plain hostnames only:
  // no wildcards, schemes, paths, ports or credentials.
  const badHost = [...(config.hosts ?? []), ...values.host].find((h) => !HOSTNAME.test(h.trim()));
  if (badHost !== undefined) {
    throw new Error(`"${badHost}" cannot be checked: hosts must be plain hostnames such as app.example.com.`);
  }
  if (values.demo) {
    options = {
      source: demoSource,
      probe: values['no-probe'] ? skipProbe : demoProber,
      publicHosts: [...demoPublicHosts, ...values.public],
      extraHosts: [...demoHosts, ...values.host],
    };
  } else {
    const token = process.env.CLOUDFLARE_API_TOKEN;
    if (!token) throw new Error('Set CLOUDFLARE_API_TOKEN to a read-only API token (or try --demo).');
    const client = createClient({ token });
    const accountId = await resolveAccountId(client, process.env.CLOUDFLARE_ACCOUNT_ID);
    options = {
      source: cloudflareSource(client, accountId),
      probe: values['no-probe'] ? skipProbe : httpProber(timeout),
      publicHosts: [...(config.public ?? []), ...values.public],
      extraHosts: [...(config.hosts ?? []), ...values.host],
    };
  }

  if (command === 'scan') {
    const findings = await scan(options);
    console.log(values.json ? renderJson(findings) : renderTable(findings, process.stdout.isTTY && !process.env.NO_COLOR));
    return failing(findings, values.strict).length > 0 ? 1 : 0;
  }

  const interval = parseInterval(values.interval);
  const webhook = values.webhook ?? process.env.TUNNELCHECK_WEBHOOK_URL;
  for (;;) {
    try {
      const bad = failing(await scan(options), values.strict);
      const fresh = newlyFailing(bad, await readState(values.state));
      console.log(`${new Date().toISOString()} ${bad.length} exposed, ${fresh.length} new`);
      for (const f of fresh) console.log(`  ${f.hostname} (${f.status}): ${f.notes.join('; ')}`);
      if (fresh.length > 0 && webhook) await sendWebhook(webhook, fresh);
      // Saved only after the alert went out, so a failed alert is retried next round.
      await writeState(values.state, bad.map((f) => f.hostname));
    } catch (err) {
      console.error(`${new Date().toISOString()} scan failed: ${(err as Error).message}`);
    }
    await sleep(interval);
  }
}

// As PID 1 in a container Node ignores these signals unless they are handled,
// which would make `docker stop` hang until it gives up and kills the process.
for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.on(signal, () => process.exit(0));
}

main().then(
  (code) => {
    process.exitCode = code;
  },
  (err: unknown) => {
    console.error(`tunnelcheck: ${err instanceof Error ? err.message : String(err)}`);
    process.exitCode = 2;
  },
);
