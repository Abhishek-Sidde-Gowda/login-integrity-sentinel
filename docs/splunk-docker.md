# Local Splunk instance (Docker)

Real Splunk Enterprise, not mocked - runs via Docker instead of a
manual splunk.com download/install. No arm64 image exists yet for
`splunk/splunk`, so it runs under amd64 emulation (`--platform
linux/amd64`); slower to start (~80s) but otherwise a fully real
instance.

## Container

```bash
docker run -d --name login-integrity-splunk --platform linux/amd64 \
  -p 8000:8000 -p 8088:8088 -p 8089:8089 \
  -e SPLUNK_START_ARGS=--accept-license \
  -e SPLUNK_GENERAL_TERMS=--accept-sgt-current-at-splunk-com \
  -e SPLUNK_PASSWORD="$SPLUNK_ADMIN_PASSWORD" \
  splunk/splunk:latest
```

Accepting `SPLUNK_GENERAL_TERMS` means agreeing to Splunk's own General
Terms (https://www.splunk.com/en_us/legal/splunk-general-terms.html) -
confirmed explicitly before first run, not assumed.

- Web UI: https://localhost:8000 (admin / password in `.splunk_docker.env`, gitignored)
- Management/REST API: https://localhost:8089
- HEC (HTTP Event Collector): http://localhost:8088 (SSL disabled for local dev simplicity)

## One-time setup after first boot

Enable HEC, create the five indexes, and create a HEC token scoped to
all of them:

```bash
MGMT="https://localhost:8089"
curl -sk -u "admin:$SPLUNK_ADMIN_PASSWORD" "$MGMT/servicesNS/nobody/splunk_httpinput/data/inputs/http/http" \
  -d "disabled=0" -d "enableSSL=0"

for idx in login_integrity_auth login_integrity_badge login_integrity_token login_integrity_ssh login_integrity_netfp; do
  curl -sk -u "admin:$SPLUNK_ADMIN_PASSWORD" "$MGMT/services/data/indexes" -d "name=$idx"
done

curl -sk -u "admin:$SPLUNK_ADMIN_PASSWORD" "$MGMT/services/data/inputs/http" \
  -d "name=login_integrity" \
  -d "index=login_integrity_auth" \
  -d "indexes=login_integrity_auth,login_integrity_badge,login_integrity_token,login_integrity_ssh,login_integrity_netfp" \
  -d "disabled=0"
# response includes the generated token - put it in .env as SPLUNK_HEC_TOKEN
```

Done once already for this instance - token is in the (gitignored) `.env`.

## Verified live (2026-09-21)

`ingestion/splunk_client.py` round-tripped real data end to end against
this container: `send_auth_events()` over HEC, then `run_search()` over
the REST API read the same events back out of
`index=login_integrity_auth`. This is the actual mechanism Phase 8's
formal live verification will exercise once the detection phases exist.

## Stopping / restarting

```bash
docker stop login-integrity-splunk    # keeps container + data
docker start login-integrity-splunk   # resume later
docker rm -f login-integrity-splunk   # destroy (indexes/token go with it)
```
