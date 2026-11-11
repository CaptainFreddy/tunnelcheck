import type { AccessApp, AccessPolicy } from './types.ts';

// Access application types that do not put a login in front of a public hostname.
const NON_GATING_TYPES = new Set([
  'bookmark',
  'saas',
  'app_launcher',
  'warp',
  'dash_sso',
  'biso',
  'infrastructure',
  'proxy_endpoint',
  'end_user',
]);

export interface Pattern {
  host: string;
  path: string;
}

/** Split "app.example.com/admin/*" into host and path. */
export function parsePattern(uri: string): Pattern {
  const bare = uri.trim().toLowerCase().replace(/^[a-z]+:\/\//, '');
  const slash = bare.indexOf('/');
  if (slash === -1) return { host: bare, path: '' };
  return { host: bare.slice(0, slash), path: bare.slice(slash + 1) };
}

function escapeRegex(text: string): string {
  return text.replace(/[.+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Cloudflare Access hostname matching: a `*` stays within one label, so
 * `*.example.com` covers `a.example.com` but neither `example.com` nor
 * `a.b.example.com`.
 */
export function hostMatches(pattern: string, hostname: string): boolean {
  const patternLabels = pattern.toLowerCase().split('.');
  const hostLabels = hostname.toLowerCase().split('.');
  if (patternLabels.length !== hostLabels.length) return false;
  return patternLabels.every((label, i) => {
    const regex = new RegExp(`^${escapeRegex(label).replace(/\*/g, '[^.]*')}$`);
    return regex.test(hostLabels[i] ?? '');
  });
}

/** Does an application path cover the site root, and with it the whole hostname? */
export function pathCoversRoot(path: string): boolean {
  return path === '' || path === '*';
}

export function appPatterns(app: AccessApp): Pattern[] {
  const uris = new Set<string>();
  if (app.domain) uris.add(app.domain);
  for (const domain of app.self_hosted_domains ?? []) uris.add(domain);
  for (const dest of app.destinations ?? []) {
    if (dest.uri && (dest.type === undefined || dest.type === 'public')) uris.add(dest.uri);
  }
  return [...uris].map(parsePattern);
}

/** Plain (wildcard-free) hostnames that Access applications put a login in front of. */
export function gatedHostnames(apps: AccessApp[]): string[] {
  return apps
    .filter((app) => !(app.type && NON_GATING_TYPES.has(app.type)))
    .flatMap((app) => appPatterns(app).map((pattern) => pattern.host))
    .filter((host) => host !== '' && !host.includes('*'));
}

export interface Coverage {
  /** The application that protects the whole hostname, if any. */
  root?: AccessApp;
  /** Paths protected by applications that leave the rest of the hostname alone. */
  paths: string[];
}

export function coverage(hostname: string, apps: AccessApp[]): Coverage {
  let root: AccessApp | undefined;
  let rootWildcards = Infinity;
  const paths: string[] = [];

  for (const app of apps) {
    if (app.type && NON_GATING_TYPES.has(app.type)) continue;
    for (const pattern of appPatterns(app)) {
      if (!hostMatches(pattern.host, hostname)) continue;
      if (!pathCoversRoot(pattern.path)) {
        paths.push(`/${pattern.path}`);
        continue;
      }
      // The most specific application wins: fewest wildcards in the hostname.
      const wildcards = pattern.host.split('*').length - 1;
      if (wildcards < rootWildcards) {
        root = app;
        rootWildcards = wildcards;
      }
    }
  }
  return { root, paths: [...new Set(paths)].sort() };
}

function matchesEveryone(policy: AccessPolicy): boolean {
  const includesEveryone = (policy.include ?? []).some((rule) => 'everyone' in rule);
  return includesEveryone && (policy.require ?? []).length === 0;
}

export type PolicyState =
  | { kind: 'ok' }
  | { kind: 'bypass'; policy: string } // Access is switched off for everyone
  | { kind: 'weak'; policy: string }; // anyone who can log in is let through

export function policyState(app: AccessApp): PolicyState {
  const policies = app.policies ?? [];
  const label = (policy: AccessPolicy) => policy.name ?? 'unnamed policy';
  const bypass = policies.find((p) => p.decision === 'bypass' && matchesEveryone(p));
  if (bypass) return { kind: 'bypass', policy: label(bypass) };
  const allowAll = policies.find((p) => p.decision === 'allow' && matchesEveryone(p));
  if (allowAll) return { kind: 'weak', policy: label(allowAll) };
  return { kind: 'ok' };
}
