# tunnelcheck

Find the Cloudflare Tunnel hostnames that anyone on the internet can open without logging in.

A hostname routed through a Cloudflare Tunnel is public unless a Cloudflare Access application sits in front of it. It is easy to add a hostname and forget the Access rule, and nothing warns you. `tunnelcheck` lists every tunnel hostname in your account, matches each one against your Access applications, and then sends one anonymous request to confirm what a stranger would actually see.

```
$ tunnelcheck scan --demo
STATUS     HOSTNAME                  TUNNEL  ACCESS APP      PROBE
OPEN       api.example.com           home    -               answered (200)
  - only /admin is behind Access; the rest of the site is not
OPEN       nas.example.com           home    -               answered (200)
  - no Access application covers this hostname
OPEN       notes.apps.example.com    lab     -               answered (200)
  - no Access application covers this hostname
OPEN       old.example.com           -       -               answered (530)
  - DNS record points at a tunnel that no longer exists
  - no Access application covers this hostname
OPEN       wiki.example.com          lab     Wiki            answered (200)
  - policy "Temporary bypass" bypasses Access for everyone
MISMATCH   paperless.example.com     lab     Paperless       answered (200)
  - an Access application covers this hostname, but an anonymous request got HTTP 200
WEAK       ha.example.com            home    Home Assistant  login page
  - policy "Anyone" allows everyone who can log in
WILDCARD   *.apps.example.com        lab     -               not probed
  - every subdomain without its own Access application is open
  - list the subdomains you use under "hosts" to have each one checked
PROTECTED  git.internal.example.com  lab     Internal tools  login page
PROTECTED  grafana.example.com       home    Grafana         login page
PROTECTED  vault.apps.example.com    lab     Vault           login page
PUBLIC     blog.example.com          home    -               answered (200)

12 hostnames: 5 open, 1 mismatch, 1 weak, 1 wildcard, 3 protected, 1 public
```

## What the statuses mean

| Status | Meaning | Fails the scan |
| --- | --- | --- |
| `OPEN` | No Access application protects the whole hostname, or a policy bypasses Access for everyone. | yes |
| `MISMATCH` | An Access application covers the hostname, but an anonymous request still got an answer. | yes |
| `WEAK` | Protected, but a policy allows everyone who can log in. | only with `--strict` |
| `WILDCARD` | A wildcard route such as `*.example.com` with no matching Access application. See below. | no |
| `PROTECTED` | An Access application covers the hostname and an anonymous request was sent to a login. | no |
| `PUBLIC` | You listed this hostname as meant to be public. | no |

## How it works

1. **Discover.** Hostnames come from two places: the ingress rules of dashboard-managed tunnels, and DNS records pointing at `<tunnel-id>.cfargotunnel.com`. The DNS pass also catches tunnels configured with a local `config.yml`.
2. **Match.** Each hostname is matched against your Access applications using Cloudflare's own rules: a `*` covers exactly one subdomain level, the most specific application wins, and an application on a path such as `/admin` does not protect the rest of the site.
3. **Probe.** One anonymous `GET /` per hostname, without following redirects. A redirect to a Cloudflare Access login counts as gated. Skip this step with `--no-probe`.

`tunnelcheck` is read-only. It only sends `GET` requests to the Cloudflare API, and it talks to nothing except that API, your own hostnames, and the webhook you configure.

## Quick start

Try it without an account:

```sh
git clone <this repository> && cd tunnelcheck
docker build -t tunnelcheck .
docker run --rm tunnelcheck scan --demo
```

Scan your own account:

```sh
docker run --rm -e CLOUDFLARE_API_TOKEN=... tunnelcheck scan

# with a config file
docker run --rm -e CLOUDFLARE_API_TOKEN=... -v ./tunnelcheck.json:/data/tunnelcheck.json:ro tunnelcheck scan
```

Without Docker you need Node 22.18 or newer: `npm ci && npm run build && node dist/cli.js scan`.

### API token

Create a custom token at **My Profile > API Tokens**. A token is built from policies, and this one needs two:

| Policy type | Resources | Permissions |
| --- | --- | --- |
| Account | your account | Cloudflare Tunnel Read, Access: Apps and Policies Read |
| Zone | all zones in that account | Zone Read, DNS Read |

Set `CLOUDFLARE_ACCOUNT_ID` as well if the token can see more than one account.

## Hostnames that are meant to be public

List them in `tunnelcheck.json` in the working directory (see `tunnelcheck.example.json`), or pass `--public` on the command line. Wildcards follow the same one-level rule as Access.

```json
{
  "public": ["blog.example.com", "*.pages.example.com"]
}
```

## Wildcard routes

A route such as `*.example.com` sends every subdomain into the tunnel, which is common when a reverse proxy sits behind it. Cloudflare then only knows the wildcard, not which subdomains exist, so they cannot be discovered or probed. (If the account has no wildcard DNS record for the route, only subdomains with their own DNS record can reach it. Those are discovered and checked like any other hostname, and the report says so.) The wildcard is reported as `WILDCARD`, and two kinds of subdomain are checked individually:

- subdomains that have their own Access application, which are found automatically
- subdomains you list under `hosts` in `tunnelcheck.json`, or pass with `--host`

```json
{
  "public": ["blog.example.com"],
  "hosts": ["notes.apps.example.com", "git.apps.example.com"]
}
```

A subdomain behind a wildcard that is neither listed nor covered by an Access application is not checked, so keep `hosts` up to date.

## Running it on a schedule

`tunnelcheck watch` scans on an interval, remembers what it found, and posts to a webhook when a hostname becomes exposed that was not exposed on the previous run.

```sh
cp tunnelcheck.example.json tunnelcheck.json   # optional
echo "CLOUDFLARE_API_TOKEN=..." > .env
echo "TUNNELCHECK_WEBHOOK_URL=https://..." >> .env
docker compose up -d
```

The webhook receives a JSON body with the message in both `text` and `content`, plus the full `findings` list.

## Using it in CI or cron

`scan` exits with `0` when nothing is exposed, `1` when something is, and `2` when the scan could not run. Add `--json` for machine-readable output.

## Options

Run `tunnelcheck --help` for the full list.

## Limitations

- The probe requests `/` only. A site that is open on a deeper path but gated at the root is judged by its Access configuration alone.
- Subdomains behind a wildcard route are only checked when they are listed under `hosts` or have their own Access application.
- Access applications defined at zone level, or in another account, are not read. If the probe sees a login for a hostname with no matching application, the report says so.
- Policy analysis looks for `everyone` rules. It does not judge whether a narrower rule, such as an email domain, is strict enough for you.

## Development

```sh
npm ci
npm test          # node:test, runs the TypeScript directly
npm run typecheck
npm run demo
```

The tool has no runtime dependencies.

## License

MIT
