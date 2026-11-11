import type { AccessApp, AccessPolicy, DnsRecord, IngressRule, Source, Tunnel, Zone } from './types.ts';

const API = 'https://api.cloudflare.com/client/v4';
const PER_PAGE = 50;

export class CloudflareError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.name = 'CloudflareError';
    this.status = status;
  }
}

interface Envelope<T> {
  success: boolean;
  errors?: { code?: number; message?: string }[];
  result: T;
  result_info?: { total_pages?: number };
}

export interface ClientOptions {
  token: string;
  fetch?: typeof fetch;
}

/** Read-only client: this module only ever issues GET requests. */
export function createClient({ token, fetch: fetchImpl = fetch }: ClientOptions) {
  async function get<T>(path: string): Promise<Envelope<T>> {
    const res = await fetchImpl(`${API}${path}`, {
      method: 'GET',
      headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
    });
    let body: Envelope<T> | undefined;
    try {
      body = (await res.json()) as Envelope<T>;
    } catch {
      // fall through to the error below
    }
    if (!res.ok || !body?.success) {
      const detail = body?.errors?.map((e) => e.message).filter(Boolean).join('; ') || res.statusText;
      const hint =
        res.status === 401 || res.status === 403
          ? ' (check that the API token is valid and has the read permissions listed in the README)'
          : '';
      throw new CloudflareError(`Cloudflare API ${res.status} on ${path}: ${detail}${hint}`, res.status);
    }
    return body;
  }

  async function getAll<T>(path: string): Promise<T[]> {
    const out: T[] = [];
    const sep = path.includes('?') ? '&' : '?';
    for (let page = 1; ; page++) {
      const body = await get<T[] | null>(`${path}${sep}page=${page}&per_page=${PER_PAGE}`);
      const items = body.result ?? [];
      out.push(...items);
      const totalPages = body.result_info?.total_pages;
      if (totalPages !== undefined ? page >= totalPages : items.length < PER_PAGE) break;
    }
    return out;
  }

  return { get, getAll };
}

export type Client = ReturnType<typeof createClient>;

/** Use the given account, or the only account the token can see. */
export async function resolveAccountId(client: Client, given?: string): Promise<string> {
  if (given) return given;
  let accounts = await client.getAll<{ id: string; name: string }>('/accounts');
  if (accounts.length === 0) {
    // A token with only the permissions this tool needs may not list accounts,
    // but every zone it can read names the account that owns it.
    const zones = await client.getAll<{ account?: { id: string; name: string } }>('/zones');
    const owners = new Map(zones.flatMap((z) => (z.account ? [[z.account.id, z.account] as const] : [])));
    accounts = [...owners.values()];
  }
  if (accounts.length === 1 && accounts[0]) return accounts[0].id;
  if (accounts.length === 0) throw new Error('The API token cannot see any Cloudflare account.');
  const list = accounts.map((a) => `  ${a.id}  ${a.name}`).join('\n');
  throw new Error(`The API token can see several accounts. Set CLOUDFLARE_ACCOUNT_ID to one of:\n${list}`);
}

export function cloudflareSource(client: Client, accountId: string): Source {
  const acc = `/accounts/${accountId}`;
  return {
    tunnels: () => client.getAll<Tunnel>(`${acc}/cfd_tunnel?is_deleted=false`),

    async ingress(tunnelId) {
      try {
        const body = await client.get<{ config?: { ingress?: IngressRule[] } | null } | null>(
          `${acc}/cfd_tunnel/${tunnelId}/configurations`,
        );
        return body.result?.config?.ingress ?? [];
      } catch (err) {
        // Tunnels configured by a local config.yml have no remote configuration.
        if (err instanceof CloudflareError && err.status === 404) return [];
        throw err;
      }
    },

    zones: () => client.getAll<Zone>(`/zones?account.id=${accountId}`),

    cnames: (zoneId) => client.getAll<DnsRecord>(`/zones/${zoneId}/dns_records?type=CNAME`),

    async accessApps() {
      const apps = await client.getAll<AccessApp>(`${acc}/access/apps`);
      for (const app of apps) {
        if (app.policies === undefined) {
          app.policies = await client.getAll<AccessPolicy>(`${acc}/access/apps/${app.id}/policies`);
        }
      }
      return apps;
    },
  };
}
