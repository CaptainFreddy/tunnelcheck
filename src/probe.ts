import type { Prober, ProbeResult } from './types.ts';

const ACCESS_LOGIN_HOST = '.cloudflareaccess.com';

/** Turn a raw HTTP answer into what it says about the gate in front of the site. */
export function classify(status: number, location: string | null, hostname: string): ProbeResult {
  if (status >= 300 && status < 400 && location) {
    try {
      const target = new URL(location, `https://${hostname}/`);
      // Access sends visitors to <team>.cloudflareaccess.com. A login path only
      // counts when it stays on the probed host, never on some other site.
      const onSameHost = target.hostname === hostname.toLowerCase();
      if (target.hostname.endsWith(ACCESS_LOGIN_HOST) || (onSameHost && target.pathname.startsWith('/cdn-cgi/access/login'))) {
        return { kind: 'gated', status };
      }
    } catch {
      // an unparseable Location header is not an Access login
    }
  }
  if (status === 401 || status === 403) return { kind: 'blocked', status };
  return { kind: 'reachable', status };
}

/** One anonymous GET to the site root, without following redirects. */
export function httpProber(timeoutMs = 10_000, fetchImpl: typeof fetch = fetch): Prober {
  return async (hostname) => {
    if (hostname.includes('*')) return { kind: 'skipped' };
    try {
      const res = await fetchImpl(`https://${hostname}/`, {
        method: 'GET',
        redirect: 'manual',
        headers: { 'User-Agent': 'tunnelcheck' },
        signal: AbortSignal.timeout(timeoutMs),
      });
      await res.body?.cancel();
      return classify(res.status, res.headers.get('location'), hostname);
    } catch (err) {
      const cause = err instanceof Error && err.cause instanceof Error ? err.cause.message : undefined;
      const message = cause ?? (err instanceof Error ? err.message : String(err));
      return { kind: 'error', message };
    }
  };
}

export const skipProbe: Prober = async () => ({ kind: 'skipped' });
