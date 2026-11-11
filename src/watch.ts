import { readFile, writeFile } from 'node:fs/promises';
import type { Finding } from './types.ts';

/** "30m", "6h", "1d" or a bare number of seconds, as milliseconds. */
export function parseInterval(text: string): number {
  const match = /^(\d+)([smhd]?)$/.exec(text.trim());
  if (!match) throw new Error(`Invalid interval "${text}". Use for example 30m, 6h or 1d.`);
  const unit = { '': 1, s: 1, m: 60, h: 3600, d: 86400 }[match[2] ?? ''] ?? 1;
  const ms = Number(match[1]) * unit * 1000;
  if (ms <= 0) throw new Error('The interval must be longer than zero.');
  return ms;
}

export async function readState(path: string): Promise<string[]> {
  try {
    const parsed: unknown = JSON.parse(await readFile(path, 'utf8'));
    return Array.isArray(parsed) ? parsed.filter((x): x is string => typeof x === 'string') : [];
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return [];
    throw err;
  }
}

export async function writeState(path: string, hostnames: string[]): Promise<void> {
  await writeFile(path, `${JSON.stringify([...hostnames].sort(), null, 2)}\n`);
}

/** Failing hostnames that were not failing on the previous run. */
export function newlyFailing(failing: Finding[], previous: string[]): Finding[] {
  const seen = new Set(previous);
  return failing.filter((f) => !seen.has(f.hostname));
}

export function alertText(findings: Finding[]): string {
  const lines = findings.map((f) => `- ${f.hostname} (${f.status}): ${f.notes.join('; ')}`);
  return `tunnelcheck: ${findings.length} newly exposed hostname(s)\n${lines.join('\n')}`;
}

/** POST a JSON alert. `text` and `content` carry the same message for chat webhooks. */
export async function sendWebhook(url: string, findings: Finding[], fetchImpl: typeof fetch = fetch): Promise<void> {
  const text = alertText(findings);
  const res = await fetchImpl(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text, content: text, findings }),
    signal: AbortSignal.timeout(10_000),
  });
  if (!res.ok) throw new Error(`Webhook answered HTTP ${res.status}`);
}
