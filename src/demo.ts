import type { AccessApp, Prober, ProbeResult, Source } from './types.ts';

// A made-up account that shows every verdict, so the tool can be demonstrated
// without touching a real Cloudflare account or real hostnames.

const HOME = 'aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa';
const LAB = 'bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb';
const DELETED = 'cccccccc-3333-4333-8333-cccccccccccc';

const team = [{ email_domain: { domain: 'example.com' } }];

const apps: AccessApp[] = [
  {
    id: 'app-grafana',
    name: 'Grafana',
    type: 'self_hosted',
    domain: 'grafana.example.com',
    policies: [{ name: 'Team', decision: 'allow', include: team }],
  },
  {
    id: 'app-internal',
    name: 'Internal tools',
    type: 'self_hosted',
    domain: '*.internal.example.com',
    policies: [{ name: 'Team', decision: 'allow', include: team }],
  },
  {
    id: 'app-ha',
    name: 'Home Assistant',
    type: 'self_hosted',
    domain: 'ha.example.com',
    policies: [{ name: 'Anyone', decision: 'allow', include: [{ everyone: {} }] }],
  },
  {
    id: 'app-api-admin',
    name: 'API admin',
    type: 'self_hosted',
    domain: 'api.example.com/admin',
    policies: [{ name: 'Team', decision: 'allow', include: team }],
  },
  {
    id: 'app-wiki',
    name: 'Wiki',
    type: 'self_hosted',
    domain: 'wiki.example.com',
    policies: [{ name: 'Temporary bypass', decision: 'bypass', include: [{ everyone: {} }] }],
  },
  {
    id: 'app-paperless',
    name: 'Paperless',
    type: 'self_hosted',
    destinations: [{ type: 'public', uri: 'paperless.example.com' }],
    policies: [{ name: 'Team', decision: 'allow', include: team }],
  },
  {
    id: 'app-vault',
    name: 'Vault',
    type: 'self_hosted',
    domain: 'vault.apps.example.com',
    policies: [{ name: 'Team', decision: 'allow', include: team }],
  },
];

export const demoSource: Source = {
  tunnels: async () => [
    { id: HOME, name: 'home' },
    { id: LAB, name: 'lab' },
  ],
  ingress: async (tunnelId) =>
    tunnelId === HOME
      ? [
          { hostname: 'grafana.example.com', service: 'http://grafana:3000' },
          { hostname: 'nas.example.com', service: 'https://nas:5001' },
          { hostname: 'ha.example.com', service: 'http://homeassistant:8123' },
          { hostname: 'blog.example.com', service: 'http://blog:80' },
          { hostname: 'api.example.com', service: 'http://api:8080' },
          { service: 'http_status:404' },
        ]
      : [
          { hostname: 'wiki.example.com', service: 'http://wiki:3000' },
          { hostname: 'paperless.example.com', service: 'http://paperless:8000' },
          { hostname: '*.apps.example.com', service: 'http://traefik:80' },
          { service: 'http_status:404' },
        ],
  zones: async () => [{ id: 'zone-1', name: 'example.com' }],
  cnames: async () => [
    { name: 'grafana.example.com', type: 'CNAME', content: `${HOME}.cfargotunnel.com` },
    // Routed by a local config.yml, so it only shows up in DNS.
    { name: 'git.internal.example.com', type: 'CNAME', content: `${LAB}.cfargotunnel.com` },
    { name: '*.apps.example.com', type: 'CNAME', content: `${LAB}.cfargotunnel.com` },
    { name: 'old.example.com', type: 'CNAME', content: `${DELETED}.cfargotunnel.com` },
    { name: 'www.example.com', type: 'CNAME', content: 'example.pages.dev' },
  ],
  accessApps: async () => apps,
};

const answers: Record<string, ProbeResult> = {
  'grafana.example.com': { kind: 'gated', status: 302 },
  'git.internal.example.com': { kind: 'gated', status: 302 },
  'ha.example.com': { kind: 'gated', status: 302 },
  'nas.example.com': { kind: 'reachable', status: 200 },
  'blog.example.com': { kind: 'reachable', status: 200 },
  'api.example.com': { kind: 'reachable', status: 200 },
  'wiki.example.com': { kind: 'reachable', status: 200 },
  'paperless.example.com': { kind: 'reachable', status: 200 },
  'old.example.com': { kind: 'reachable', status: 530 },
  'vault.apps.example.com': { kind: 'gated', status: 302 },
  'notes.apps.example.com': { kind: 'reachable', status: 200 },
};

export const demoProber: Prober = async (hostname) => answers[hostname] ?? { kind: 'skipped' };

export const demoPublicHosts = ['blog.example.com'];

// A subdomain served by the *.apps.example.com wildcard route.
export const demoHosts = ['notes.apps.example.com'];
