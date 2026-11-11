import { discoverHosts, expandHosts, type Host } from './discover.ts';
import { coverage, hostMatches, policyState, type Coverage } from './match.ts';
import type { Finding, Prober, ProbeResult, Source, Status } from './types.ts';

const PROBE_CONCURRENCY = 8;

export interface ScanOptions {
  source: Source;
  probe: Prober;
  /** Hostname patterns that are meant to be open to everyone. */
  publicHosts?: string[];
  /** Extra hostnames to check, typically subdomains served by a wildcard route. */
  extraHosts?: string[];
}

/** Combine what the configuration says with what an anonymous request saw. */
export function decide(host: Host, cov: Coverage, probe: ProbeResult, isPublic: boolean): Finding {
  const notes: string[] = [];
  const finding = (status: Status): Finding => ({
    hostname: host.hostname,
    status,
    tunnel: host.tunnelName,
    app: cov.root?.name ?? cov.root?.id,
    probe,
    notes,
  });

  if (host.dangling) notes.push('DNS record points at a tunnel that no longer exists');
  if (host.unrouted) notes.push('no tunnel route in this account matches this hostname');
  if (probe.kind === 'error') notes.push(`probe failed: ${probe.message}`);

  if (!cov.root) {
    if (host.hostname.includes('*')) {
      if (host.inDns) {
        notes.push('every subdomain without its own Access application is open');
        notes.push('list the subdomains you use under "hosts" to have each one checked');
      } else {
        // Without a wildcard DNS record, a subdomain only resolves if it has a record of its own.
        notes.push('no wildcard DNS record in this account points at this route');
        notes.push('only subdomains with their own DNS record can reach it, and those are checked individually');
      }
      return finding('wildcard');
    }
    // Listing a hostname as public only excuses it for being open.
    if (isPublic && probe.kind !== 'gated') return finding('public');
    if (cov.paths.length > 0) {
      notes.push(`only ${cov.paths.join(', ')} is behind Access; the rest of the site is not`);
    } else {
      notes.push('no Access application covers this hostname');
    }
    if (probe.kind === 'gated') {
      notes.push('an Access login was seen anyway; it may come from an application outside this account');
      return finding('protected');
    }
    if (probe.kind === 'blocked') {
      notes.push(`an anonymous request got HTTP ${probe.status}, so something other than Access may be refusing it`);
    }
    return finding('open');
  }

  const state = policyState(cov.root);
  if (state.kind === 'bypass') {
    notes.push(`policy "${state.policy}" bypasses Access for everyone`);
    return finding('open');
  }
  if (probe.kind === 'reachable') {
    notes.push(`an Access application covers this hostname, but an anonymous request got HTTP ${probe.status}`);
    return finding('mismatch');
  }
  if (state.kind === 'weak') {
    notes.push(`policy "${state.policy}" allows everyone who can log in`);
    return finding('weak');
  }
  return finding('protected');
}

async function mapLimit<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const results = new Array<R>(items.length);
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const index = next++;
      results[index] = await fn(items[index] as T);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return results;
}

export async function scan({ source, probe, publicHosts = [], extraHosts = [] }: ScanOptions): Promise<Finding[]> {
  const [routed, apps] = await Promise.all([discoverHosts(source), source.accessApps()]);
  const hosts = expandHosts(routed, apps, extraHosts);
  return mapLimit(hosts, PROBE_CONCURRENCY, async (host) => {
    const isPublic = publicHosts.some((pattern) => hostMatches(pattern, host.hostname));
    return decide(host, coverage(host.hostname, apps), await probe(host.hostname), isPublic);
  });
}

/** Statuses that make a scan fail. `weak` only counts in strict mode. */
export function failing(findings: Finding[], strict: boolean): Finding[] {
  return findings.filter(
    (f) => f.status === 'open' || f.status === 'mismatch' || (strict && f.status === 'weak'),
  );
}
