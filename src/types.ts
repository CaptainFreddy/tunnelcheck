// Shapes of the Cloudflare API objects we read, trimmed to the fields we use.

export interface Tunnel {
  id: string;
  name: string;
}

export interface IngressRule {
  hostname?: string;
  service?: string;
  path?: string;
}

export interface Zone {
  id: string;
  name: string;
}

export interface DnsRecord {
  name: string;
  type: string;
  content: string;
}

export type AccessRule = Record<string, unknown>;

export interface AccessPolicy {
  name?: string;
  /** allow, deny, non_identity (service auth) or bypass; kept open so new values fail closed. */
  decision: string;
  include?: AccessRule[];
  require?: AccessRule[];
  exclude?: AccessRule[];
}

export interface AccessApp {
  id: string;
  name?: string;
  type?: string;
  domain?: string;
  self_hosted_domains?: string[];
  destinations?: { type?: string; uri?: string }[];
  policies?: AccessPolicy[];
}

/** Everything the scanner needs to read. Implemented by the real API client and by the demo. */
export interface Source {
  tunnels(): Promise<Tunnel[]>;
  ingress(tunnelId: string): Promise<IngressRule[]>;
  zones(): Promise<Zone[]>;
  cnames(zoneId: string): Promise<DnsRecord[]>;
  accessApps(): Promise<AccessApp[]>;
}

export type ProbeResult =
  | { kind: 'gated'; status: number } // redirected to a Cloudflare Access login
  | { kind: 'blocked'; status: number } // refused with 401/403
  | { kind: 'reachable'; status: number } // answered without any gate
  | { kind: 'error'; message: string }
  | { kind: 'skipped' };

export type Prober = (hostname: string) => Promise<ProbeResult>;

export type Status = 'open' | 'mismatch' | 'weak' | 'wildcard' | 'protected' | 'public';

export interface Finding {
  hostname: string;
  status: Status;
  tunnel?: string;
  app?: string;
  probe: ProbeResult;
  notes: string[];
}
