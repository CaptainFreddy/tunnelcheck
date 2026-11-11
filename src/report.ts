import type { Finding, ProbeResult, Status } from './types.ts';

const ORDER: Status[] = ['open', 'mismatch', 'weak', 'wildcard', 'protected', 'public'];

const COLORS: Record<Status, string> = {
  open: '\x1b[1;31m',
  mismatch: '\x1b[1;31m',
  weak: '\x1b[33m',
  wildcard: '\x1b[36m',
  protected: '\x1b[32m',
  public: '\x1b[2m',
};
const RESET = '\x1b[0m';

function probeText(probe: ProbeResult): string {
  switch (probe.kind) {
    case 'gated':
      return 'login page';
    case 'blocked':
      return `refused (${probe.status})`;
    case 'reachable':
      return `answered (${probe.status})`;
    case 'error':
      return 'failed';
    case 'skipped':
      return 'not probed';
  }
}

export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort(
    (a, b) => ORDER.indexOf(a.status) - ORDER.indexOf(b.status) || a.hostname.localeCompare(b.hostname),
  );
}

export function renderTable(findings: Finding[], color: boolean): string {
  if (findings.length === 0) return 'No tunnel hostnames found in this account.';
  const header = ['STATUS', 'HOSTNAME', 'TUNNEL', 'ACCESS APP', 'PROBE'];
  const rows = sortFindings(findings).map((f) => ({
    finding: f,
    cells: [f.status.toUpperCase(), f.hostname, f.tunnel ?? '-', f.app ?? '-', probeText(f.probe)],
  }));
  const widths = header.map((h, i) => Math.max(h.length, ...rows.map((r) => (r.cells[i] ?? '').length)));
  const line = (cells: string[]) => cells.map((c, i) => c.padEnd(widths[i] ?? 0)).join('  ').trimEnd();

  const out = [line(header)];
  for (const { finding, cells } of rows) {
    const text = line(cells);
    const status = cells[0] ?? '';
    out.push(color ? `${COLORS[finding.status]}${status}${RESET}${text.slice(status.length)}` : text);
    for (const note of finding.notes) out.push(`  - ${note}`);
  }

  const counts = ORDER.map((s) => [s, findings.filter((f) => f.status === s).length] as const)
    .filter(([, n]) => n > 0)
    .map(([s, n]) => `${n} ${s}`);
  out.push('', `${findings.length} hostnames: ${counts.join(', ')}`);
  return out.join('\n');
}

export function renderJson(findings: Finding[]): string {
  return JSON.stringify(sortFindings(findings), null, 2);
}
