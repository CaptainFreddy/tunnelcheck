import { gatedHostnames, hostMatches } from './match.ts';
import type { AccessApp, Source } from './types.ts';

const TUNNEL_SUFFIX = '.cfargotunnel.com';

export interface Host {
  hostname: string;
  tunnelId?: string;
  tunnelName?: string;
  /** The DNS record points at a tunnel that no longer exists. */
  dangling: boolean;
  /** A DNS record for exactly this hostname points at the tunnel. */
  inDns?: boolean;
  /** Listed by the user, but no tunnel route in the account matches it. */
  unrouted?: boolean;
}

/**
 * Collect every public hostname that routes into a tunnel, from two places:
 * the tunnel's own ingress rules (dashboard-managed tunnels) and DNS records
 * pointing at <tunnel-id>.cfargotunnel.com (which also catches tunnels
 * configured by a local config.yml).
 */
export async function discoverHosts(source: Source): Promise<Host[]> {
  const tunnels = await source.tunnels();
  const names = new Map(tunnels.map((t) => [t.id, t.name]));
  const hosts = new Map<string, Host>();

  for (const tunnel of tunnels) {
    for (const rule of await source.ingress(tunnel.id)) {
      if (!rule.hostname) continue; // the catch-all rule has no hostname
      const hostname = rule.hostname.toLowerCase();
      hosts.set(hostname, { hostname, tunnelId: tunnel.id, tunnelName: tunnel.name, dangling: false });
    }
  }

  for (const zone of await source.zones()) {
    for (const record of await source.cnames(zone.id)) {
      const target = record.content.toLowerCase().replace(/\.$/, '');
      if (!target.endsWith(TUNNEL_SUFFIX)) continue;
      const hostname = record.name.toLowerCase();
      const known = hosts.get(hostname);
      if (known) {
        known.inDns = true;
        continue;
      }
      const tunnelId = target.slice(0, -TUNNEL_SUFFIX.length);
      const tunnelName = names.get(tunnelId);
      hosts.set(hostname, { hostname, tunnelId, tunnelName, dangling: tunnelName === undefined, inDns: true });
    }
  }

  return [...hosts.values()].sort((a, b) => a.hostname.localeCompare(b.hostname));
}

/**
 * A wildcard route such as `*.example.com` hides the subdomains that really
 * exist behind it. Add the ones we can know about: hostnames the user listed,
 * and hostnames that have their own Access application.
 */
export function expandHosts(hosts: Host[], apps: AccessApp[], extraHosts: string[]): Host[] {
  const all = new Map(hosts.map((h) => [h.hostname, h]));
  const wildcards = hosts.filter((h) => h.hostname.includes('*'));
  const routeFor = (hostname: string) => wildcards.find((w) => hostMatches(w.hostname, hostname));

  for (const hostname of gatedHostnames(apps)) {
    const route = routeFor(hostname);
    if (route && !all.has(hostname)) all.set(hostname, { ...route, hostname });
  }
  for (const raw of extraHosts) {
    const hostname = raw.trim().toLowerCase();
    if (all.has(hostname)) continue;
    const route = routeFor(hostname);
    all.set(hostname, route ? { ...route, hostname } : { hostname, dangling: false, unrouted: true });
  }
  return [...all.values()].sort((a, b) => a.hostname.localeCompare(b.hostname));
}
