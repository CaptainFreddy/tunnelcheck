# tunnelcheck

Find the Cloudflare Tunnel hostnames that anyone can open without logging in.

A tunnel hostname is public unless a Cloudflare Access application sits in front of it, and nothing warns you when you forget one. `tunnelcheck` lists every tunnel hostname in your account, matches it against your Access applications, and sends one anonymous request to confirm.

```
$ tunnelcheck scan
STATUS     HOSTNAME                TUNNEL  ACCESS APP      PROBE
OPEN       nas.example.com         home    -               answered (200)
  - no Access application covers this hostname
MISMATCH   paperless.example.com   lab     Paperless       answered (200)
  - an Access application covers this hostname, but an anonymous request got HTTP 200
WEAK       ha.example.com          home    Home Assistant  login page
  - policy "Anyone" allows everyone who can log in
PROTECTED  grafana.example.com     home    Grafana         login page
PUBLIC     blog.example.com        home    -               answered (200)
```

Read-only, no runtime dependencies, and it only talks to Cloudflare and your own hostnames.

## Usage

```sh
docker build -t tunnelcheck .

# try it on a built-in fake account
docker run --rm tunnelcheck scan --demo

# scan your own account
docker run --rm -e CLOUDFLARE_API_TOKEN=... tunnelcheck scan
```

The scan exits with `1` when something is exposed, so it works in CI and cron. Run `tunnelcheck --help` for all options.

## API token

Create a custom token under **My Profile > API Tokens** with two policies:

| Policy type | Permissions |
| --- | --- |
| Account | Cloudflare Tunnel Read, Access: Apps and Policies Read |
| Zone | Zone Read, DNS Read |

## Statuses

| Status | Meaning |
| --- | --- |
| `OPEN` | Nothing protects the hostname. Fails the scan. |
| `MISMATCH` | An Access application exists, but the site still answers anonymously. Fails the scan. |
| `WEAK` | Protected, but a policy allows everyone who can log in. Fails with `--strict`. |
| `WILDCARD` | A wildcard route such as `*.example.com`. List its subdomains under `hosts` to check them. |
| `PROTECTED` | Behind an Access login. |
| `PUBLIC` | Open, and listed by you as meant to be public. |

## Configuration

Optional `tunnelcheck.json` in the working directory (`/data` in the container):

```json
{
  "public": ["blog.example.com"],
  "hosts": ["notes.apps.example.com"]
}
```

`public` lists hostnames that are meant to be open. `hosts` lists extra hostnames to check, such as subdomains behind a wildcard route.

## Scheduled scans

`tunnelcheck watch` rescans on an interval and posts to a webhook when a new hostname becomes exposed.

```sh
echo "CLOUDFLARE_API_TOKEN=..." > .env
echo "TUNNELCHECK_WEBHOOK_URL=https://..." >> .env   # optional
docker compose up -d
```

## Limitations

- Only `/` is probed, so a site that is open on a deeper path is judged by its Access configuration alone.
- Access applications defined at zone level or in another account are not read.

## License

MIT
