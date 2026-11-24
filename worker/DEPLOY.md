# Hosted door (Cloudflare Workers Free)

The door runs as one Worker plus one SQLite-backed Durable Object. Read tools (`door_rules`,
`list_facts`, `lookup_fact`, `who_am_i`) touch no storage. Act tools (`request_call`, `ask_question`,
`leave_lead`, `check_request`) are decided inside the Durable Object.

Host rule: the door never runs on a machine that holds anything private, and the owner's machine is
never opened to inbound traffic. The Worker holds only the public facts page's words, its own state
(asks, answers, declines, caps, receipts) and the sha256 of the owner's pull token.

## Free plan, hard caps (checked 2026-11-24)

- Workers (developers.cloudflare.com/workers/platform/pricing + /limits): 100,000 requests/day,
  10 ms CPU per request; over the limit Cloudflare returns error 1027 instead of billing.
- Durable Objects (developers.cloudflare.com/durable-objects/platform/pricing + /limits): the Free plan
  can only create SQLite-backed Durable Objects. Free: 100,000 requests/day, 13,000 GB-s/day,
  5 million rows read/day, 100,000 rows written/day, 5 GB stored. "If you exceed any one of the free
  tier limits, further operations of that type will fail with an error."
- Rate limiting bindings: per address 30 requests/minute, whole door 600/minute per location.
- Keep the account on Workers Free. Upgrading to Workers Paid is the only way this can bill.

## Caller identity (Web Bot Auth)

`src/identity.js` checks a request's Web Bot Auth signature before any tool runs (`identity` in
`src/door.config.json`). No signature: the caller is labeled self reported and can do everything.
A valid signature with the key at `https://<domain>/.well-known/http-message-signatures-directory`:
labeled `verified: <domain>`. A signature that fails: HTTP 401, a reason code, a pointer to the
standard and an `Accept-Signature` header. The only outbound request the Worker makes is a GET of a
signed caller's key directory (cached at most 5 minutes; a Free plan Worker may make 50 per request).
One-time nonces are kept in the Durable Object. `min_trust` can require a level per ask (empty here).

```sh
node worker/test/identity_vectors.mjs                     # Worker verifier vs RFC/draft vectors + Python reference
uv run python worker/test/identity_e2e.py https://<door> --key-file <signer key> [--call]
```

## Deploy

```sh
uv run python worker/build_facts.py      # fetches the LIVE facts page, writes src/facts.json (sha256 recorded)
cd worker && npx wrangler@4.168.0 deploy
# owner token: made and kept on the owner's machine (chmod 600); only its sha256 goes to the Worker
python3 -c "import hashlib,sys;print(hashlib.sha256(open(sys.argv[1]).read().strip().encode()).hexdigest())" TOKEN_FILE \
  | npx wrangler@4.168.0 secret put OWNER_TOKEN_SHA256
cd .. && uv run python worker/test/outside_client.py https://<door>/mcp
```

Any edit to the facts page changes its sha256: rebuild, deploy and re-run the outside check.

## Owner side

`owner/afd_owner.py poll` every minute (launchd, cron or systemd) with `AFD_DOOR_URL`,
`AFD_TOKEN_FILE`, `AFD_OWNER_CHAT_USER` (and optionally `AFD_NOTIFY_TARGET`, default `telegram`).
It only connects out. `AFD_SENDER=stdout` is a dry run.

## Local test

```sh
cd worker && echo "OWNER_TOKEN_SHA256=<sha256 of a test token>" > .dev.vars   # git-ignored
npx wrangler@4.168.0 dev --port 8787
python3 worker/test/act_e2e.py http://127.0.0.1:8787 --token-file <test token file> --owner-sim --cap
uv run python worker/test/identity_e2e.py http://127.0.0.1:8787 --key-file <signer key> --call --unsigned-call
```

## Undo

See [../UNDO.md](../UNDO.md).
