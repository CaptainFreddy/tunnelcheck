# tunnelcheck

Find the Cloudflare Tunnel hostnames that anyone can open without logging in.

A hostname routed through a Cloudflare Tunnel is public unless a Cloudflare Access application sits in front of it. Adding a hostname and forgetting the Access rule is easy, and nothing warns you. `tunnelcheck` lists every tunnel hostname in your account, matches each against your Access applications, and sends one anonymous request to confirm what a stranger would see.

```
$ tunnelcheck scan
STATUS     HOSTNAME                TUNNEL  ACCESS APP      PROBE
OPEN       nas.example.com         home    -               answered (200)
  - no Access application covers this hostname
OPEN       api.example.com         home    -               answered (200)
  - only /admin is behind Access; the rest of the site is not
MISMATCH   paperless.example.com   lab     Paperless       answered (200)
  - an Access application covers this hostname, but an anonymous request got HTTP 200
WEAK       ha.example.com          home    Home Assistant  login page
  - policy "Anyone" allows everyone who can log in
PROTECTED  grafana.example.com     home    Grafana         login page
PUBLIC     blog.example.com        home    -               answered (200)
```

- **Read-only.** It only sends `GET` requests to the Cloudflare API.
- **No runtime dependencies.** The image contains Node and the compiled tool, nothing else.
- **Private.** It talks to the Cloudflare API, your own hostnames, and a webhook if you set one.

## Quick start

Try it on a built-in fake account:

```sh
docker build -t tunnelcheck .
docker run --rm tunnelcheck scan --demo
```

Scan your own account:

```sh
docker run --rm -e CLOUDFLARE_API_TOKEN=... tunnelcheck scan
```

## API token

Create a custom token under **My Profile > API Tokens** with two policies:

| Policy type | Resources | Permissions |
| --- | --- | --- |
| Account | your account | Cloudflare Tunnel Read, Access: Apps and Policies Read |
| Zone | all zones in that account | Zone Read, DNS Read |

Set `CLOUDFLARE_ACCOUNT_ID` only if the token can see more than one account.

## Statuses

| Status | Meaning | Fails the scan |
| --- | --- | --- |
| `OPEN` | Nothing protects the whole hostname, or a policy lets everyone through without a login. | yes |
| `MISMATCH` | An Access application covers the hostname, but an anonymous request still got an answer. | yes |
| `WEAK` | Protected, but a policy allows everyone who can log in. | with `--strict` |
| `WILDCARD` | A wildcard route such as `*.example.com`. See [Wildcard routes](#wildcard-routes). | no |
| `PROTECTED` | Covered by an Access application, and an anonymous request was sent to a login. | no |
| `PUBLIC` | Open, and listed by you as meant to be public. | no |

Exit codes: `0` nothing exposed, `1` something exposed, `2` the scan could not run.

## Configuration

Put a `tunnelcheck.json` in the working directory, or point to one with `--config`:

```json
{
  "public": ["blog.example.com"],
  "hosts": ["notes.apps.example.com"]
}
```

| Key | Purpose |
| --- | --- |
| `public` | Hostnames that are meant to be open. Wildcards cover one subdomain level, as in Access. |
| `hosts` | Extra hostnames to check. Used for subdomains behind a wildcard route. |

With Docker, mount the file into `/data`:

```sh
docker run --rm -e CLOUDFLARE_API_TOKEN=... \
  -v ./tunnelcheck.json:/data/tunnelcheck.json:ro tunnelcheck scan
```

## Options

| Option | Purpose |
| --- | --- |
| `--json` | Print JSON instead of a table. |
| `--strict` | Also fail on `WEAK`. |
| `--no-probe` | Only read the configuration; send no requests to your hostnames. |
| `--public <host>` | Same as `public` in the config file. Repeatable. |
| `--host <host>` | Same as `hosts` in the config file. Repeatable. |
| `--config <file>` | Path to the config file. |
| `--timeout <ms>` | Probe timeout per hostname. Default `10000`. |
| `--demo` | Use the built-in fake account. |

## Scheduled scans and alerts

`tunnelcheck watch` rescans on an interval and posts to a webhook when a hostname becomes exposed that was not exposed on the previous run.

```sh
echo "CLOUDFLARE_API_TOKEN=..." > .env
echo "TUNNELCHECK_WEBHOOK_URL=https://..." >> .env   # optional
docker compose up -d
```

| Option | Purpose |
| --- | --- |
| `--interval <time>` | Time between scans, such as `30m`, `6h` or `1d`. Default `6h`. |
| `--webhook <url>` | Where to post alerts. Also read from `TUNNELCHECK_WEBHOOK_URL`. |
| `--state <file>` | Where findings are remembered between runs. |

The webhook receives JSON with the message in `text` and `content`, plus the full `findings` list.

## How it works

1. **Discover.** Hostnames come from the ingress rules of dashboard-managed tunnels and from DNS records that point at `<tunnel-id>.cfargotunnel.com`. The DNS pass also catches tunnels configured with a local `config.yml`.
2. **Match.** Each hostname is matched against your Access applications using Cloudflare's rules: a `*` covers exactly one subdomain level, the most specific application wins, and an application on a path such as `/admin` does not protect the rest of the site.
3. **Probe.** One anonymous `GET /` per hostname, without following redirects. Only a redirect to a Cloudflare Access login counts as gated.

## Wildcard routes

A route such as `*.example.com` sends every subdomain into the tunnel, which is common with a reverse proxy behind it. Cloudflare then knows the wildcard but not which subdomains exist. What the report says depends on your DNS:

- **No wildcard DNS record.** Only subdomains with their own DNS record can reach the route. Those are discovered and checked like any other hostname.
- **A wildcard DNS record.** Every subdomain is reachable. Subdomains with their own Access application are checked automatically; list the others under `hosts`.

## Limitations

- The probe requests `/` only. A site that is open on a deeper path is judged by its Access configuration alone.
- Behind a wildcard DNS record, a subdomain is only checked when it is listed under `hosts` or has its own Access application.
- Access applications defined at zone level or in another account are not read. If the probe sees a login for a hostname with no matching application, the report says so.
- Policy analysis looks for `everyone` rules. It does not judge whether a narrower rule, such as an email domain, is strict enough.

## Development

Requires Node 22.18 or newer.

```sh
npm ci --ignore-scripts
npm test
npm run typecheck
npm run demo
```

## License

MIT
