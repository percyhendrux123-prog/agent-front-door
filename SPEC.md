# Agent Front Door: spec

Status: open source (MIT). Python prototype in `agent_front_door/`; hosted version for Cloudflare Workers Free in `worker/` with the owner side in `owner/` (see the Hosted door section). Owner of every go-live decision: the business owner.

Fixed rule: the door never runs on a machine that holds anything private. Host it on its own small box or container that holds only the public facts page and its own deploy config.

## Page one, in plain English

**What it is.** A front door for AI agents. Today a person visits deployaxiom.com and reads the page. Tomorrow, more of those visits come from someone's assistant: ChatGPT, Claude, Gemini, or another Hermes, sent to find a firm and set up a call. The front door is the one place those agents can knock. It speaks MCP, the common plug that all of the major assistants already use, so it does not care which company made the agent.

**What an outside agent can do.**
1. **Read.** Get the facts about the business. They come straight off the human facts page, word for word. The door cannot say anything the page does not say, and it shows no price the page does not show.
2. **Ask or act.** Request a call, ask a question, or leave a lead. Each one goes through the owner's rules, the same ones already built for Hermes agents (hermes-consent-network):
   - On the allowed list: it goes through.
   - Not on the list: the owner gets **one** yes/no question. Nothing happens until he answers.
   - The owner said no before: refused, and he is not asked again.
   - The hard floor, always refused, for everyone: prices, payments, refunds, deleting data, sending messages to anyone else, client data or passwords, and commitments in the owner's name.
3. **Say who it is.** Every agent names itself, its model, and the person it acts for. That goes into a receipt.

**What it never does.** It never sends an email or text, never books the calendar, never takes money. In the prototype the only effect of an approved request is one line in the owner's local inbox. A caller's typed note is cut to 280 characters, links are removed, and only the owner reads it. It is never fed to our own AI, so a hostile note cannot steer our agents.

**Receipts on both sides.** Every decision writes a line to a tamper-evident log (each line carries the fingerprint of the one before; change one and the chain breaks). The caller gets its copy in every answer, so both sides can prove what happened.

**Why it matters beyond Axiom.** One config file describes one business: its facts page, its owner, its rules. Copy the file and any business has a front door: Axiom first, then clients, then anyone who installs it. It is open source (MIT), so it can become the common way agents do business with each other under the owner's consent, instead of every company inventing its own.

**What the owner decides.** Whether and when a door goes live, and on what terms. Nothing in this repo puts a door online by itself.

---

## Technical part

### Tools (MCP)

| Tool | Kind | What it does |
|---|---|---|
| `door_rules` | read | The rules above, for the calling model. Also sent as server `instructions` on connect. |
| `list_facts` | read | Every fact on the facts page (id, question, answer, links), the page URL and the page's sha256. |
| `lookup_fact(question)` | read | The one fact that answers a question, by word overlap with a small synonym list. Returns `found: false` instead of stretching. No model involved. |
| `request_call(caller_agent, caller_model, acting_for, contact_email, topic, preferred_window, note?, caller_key?)` | act | Asks for a call for a person. |
| `ask_question(caller..., question, contact_email)` | act | Answered from the page if a fact matches strongly (score >= 0.75); otherwise an act under the rules. |
| `leave_lead(caller..., contact_email, topic, note?)` | act | Leaves a lead. |
| `check_request(request_id, caller...)` | act | Collects the owner's answer. A yes executes once; a second check records nothing new. |

`topic` and `preferred_window` are fixed lists, not free text. Act tools carry `idempotent_hint` and no tool is destructive. Transports: stdio (`afd-server`) and streamable HTTP (`afd-server --http`, 127.0.0.1 only in the prototype).

### Data source

`config/axiom.yaml` points at the facts page HTML (`facts_file`) and its public URL. The parser takes each `<h2>` inside `<article>` as a question and the paragraphs and list items under it as the answer, tags stripped, whitespace collapsed, nothing else changed. There is no second copy of the facts to drift.

- Test `test_every_fact_is_the_page_word_for_word`: every answer line appears verbatim in the page's visible text.
- Test `test_no_price_appears_unless_the_page_shows_one`: no `$` amount in the output.
- Test `test_live_page_text_matches_snapshot_if_available`: the snapshot in `data/` is byte-identical to the site's own build copy (set `AFD_LIVE_FACTS_FILE`; skipped otherwise). Production should read the deployed page (or the same build artifact) at start, and expose `page_sha256` so a caller can check it against the live page.

### Consent mapping

Built on `hermes-consent-network` `core.py`, vendored as `agent_front_door/consent_core.py` (same MIT author; one change: receipts carry `caller_agent`, `caller_model`, `acting_for`, `identity`). Policy files use the same YAML shape as consent-network peers.

| Consent network | Front door |
|---|---|
| peer (A2A identity) | `public` for strangers; `partners/<slug>.yaml` for a caller that presents the key whose sha256 is in that file |
| ask type | the action: `request_call`, `ask_question`, `leave_lead` |
| `allow` / `ask_owner` / `deny` | same; Axiom's `public.yaml`: allow `leave_lead`; ask owner `request_call`, `ask_question` |
| hard floor `HARD_DENY` | same set plus `commitment` and `client_data`, triggered by the action or by words in the caller's text |
| one question to owner | `OwnerChannel`; prototype writes `.state/owner_channel.jsonl`, hosted: the owner's machine pulls the question and sends it with Hermes `send` to the owner's chat, with the session mirror off. Owner replies `consent yes CODE` / `consent no CODE` (prototype: `afd yes CODE`) |
| remembered no | `Declines`, keyed by caller agent + person, 90 days, similarity 0.6 |
| `max_pending` | per caller (public: 2) |
| receipts | `Receipts` hash chain in `.state/receipts.jsonl`; each answer returns `{seq, ts, ask_id, ask_type, decision, reason, text_sha256, prev, hash}` so the caller keeps its own chain; `compare_sides` cross-checks |

Decision order for every act: validate labels and email, rate cap, hard floor, prior owner answer for this exact ask, policy (deny / allow), remembered no, pending cap, daily owner cap, then one owner question.

Identity is **self-reported** unless a partner key matches. Self-reported names are recorded and shown to the owner as such; they never unlock an allow-list.

### Agent identity (Web Bot Auth)

Plain English: see [docs/IDENTITY-ONE-PAGER.md](docs/IDENTITY-ONE-PAGER.md). Research and sources: [docs/IDENTITY-RESEARCH.md](docs/IDENTITY-RESEARCH.md).

**Standard.** Callers sign HTTP requests per draft-ietf-webbotauth-httpsig-protocol-01 (RFC 9421 HTTP Message Signatures, Ed25519). Keys are a JWK Set at `https://<owner-domain>/.well-known/http-message-signatures-directory`, served as `application/http-message-signatures-directory+json`. `keyid` is the RFC 7638/8037 thumbprint and the verifier computes it itself, never trusting a `kid` label. `agent_front_door/identity.py` reproduces RFC 9421 B.2.6 and the draft's E.2.1 Ed25519 vectors.

**Door profile (stricter than the draft minimum).** Covered components must include `@method`, `@authority` (or `@target-uri`), `@path`, `content-digest` (RFC 9530 sha-256 of the body), `"signature-agent";key=<label>`, and `@query` when there is a query. Required params: `created`, `expires` (lifetime at most 300 s, skew 60 s), `keyid`, `nonce` (at least 16 chars, single use per agent URL until expiry), `tag="web-bot-auth"`, and `alg` absent or `ed25519`. The signature base uses the door's configured authority (`identity.authority`), not the request's Host header, so a signature made for another door fails.

**Directory response signature.** The draft says a verifier relying on the domain MUST check the directory response's own signatures. Both verifiers (Python and the Worker) keep only keys that signed the response for the directory's host: `Signature-Input` with `tag="http-message-signatures-directory"`, keyid = that key's thumbprint, covering `"@authority";req`, in date (lifetime at most 90 days so a static host can serve fixed headers). A copy of the file and headers on another host gives no keys. `tools/key_directory.py` writes the file and the headers.

**Key discovery.** The verifier fetches the `Signature-Agent` URL with GET, no redirects, a 3 s timeout and a 64 KB cap. It must be https, a DNS name (not an IP literal, localhost or a .local name), on the default port, with no credentials. Cache time is `min(publisher max-age, identity.key_cache_s)`, default 300 s. That is the revocation window. A failed refresh keeps already-held keys for at most one extra negative-cache period (60 s) and never extends trust beyond that. Lookup is by (URL, thumbprint), as the draft requires.

**Levels.**

| Level | Meaning | Door policy |
|---|---|---|
| `unsigned` | No signature, or the key directory was unreachable | `public.yaml`: may ask for a call; the owner sees "self reported". (`identity.min_trust` can require a level per ask; Axiom's is empty.) |
| `signed` | Valid signature; the key URL is not a domain's well-known path | Treated as public; principal = `key:<thumbprint>` |
| `domain_verified` | Valid signature; key published at the domain's well-known path | `verified.yaml` (`request_call` asks the owner) |
| `partner` | Domain-verified, and `policies/partners/<x>.yaml` names that `domain:` | That partner's allow-list |

A presented signature that fails (forged key, wrong domain, replay, expired, tampered body, revoked) gets HTTP **401** with a reason code and `Accept-Signature`, and the MCP server never sees the request. An unsigned request is not penalised. Identity is carried in the ASGI scope state from `IdentityMiddleware`. Tool arguments and custom headers cannot set it. `who_am_i` shows the caller how the door sees it.

**Principal.** Rate caps, pending caps, owner-answer binding and remembered no's key on the verified domain (or key thumbprint), not on the self-typed `caller_agent`.

**Receipts.** The door log adds `identity`, `identity_label`, `principal`, `verified_domain`, `signature_agent`, `keyid` and `request_sig_sha256` (sha256 of the caller's signature bytes). The receipt returned to the caller carries `door_signature` (Ed25519 over the receipt's chain hash and decision fields, with the door key's thumbprint and key URL). The door serves its own directory at the well-known path, and `identity.verify_receipt` checks it on the caller side.

**Revocation.** The owner of the caller's domain removes the key (or sets JWK `exp`), and doors stop trusting it within `key_cache_s`. The door owner can list `identity.revoked_keyids` or `identity.revoked_agents` for an immediate local block.

**Limits.** This proves which domain's owner stands behind a request. It does not prove that owner is honest, that the named person (`acts_for`) agreed, or that the ask is wise. Those stay with the consent rules and the owner. stdio clients can't carry HTTP signatures and are always `unsigned`. The Python door's nonce store is in memory. The hosted Worker (`worker/src/identity.js`, a port that gives the same level and reason as `identity.py` on every shared vector, `worker/test/identity_vectors.mjs`) keeps nonces in its Durable Object, so a replay is refused across all instances. The Worker does not sign its receipts yet (it would need a door key as a Worker secret); its receipts carry the identity fields and the caller's signature hash.

**Consent network.** The same `identity.py` ships in hermes-consent-network. A verified domain becomes the peer name. Peer files can require `partner` or `domain_verified` per ask type. A2A token peers count as partners, since the owner issued them a credential.

### Abuse limits

- Rate caps: 60 reads per minute per caller; 5 acts per hour per caller agent and per person acted for; 2 open owner questions per public caller; 10 owner questions per day across everyone. All in `config/axiom.yaml`.
- Free text: notes capped at 280 characters; links, control characters and bidi overrides removed; labels limited to 64 plain characters. Caller text is never passed to any model, only stored for the owner and shown as "their words, unverified".
- Floor words: price, payment, refund, deletion, sends to others, client data or credentials, commitments. A hit is refused before policy, for partners too, and the reply quotes the page (for price: "The scope, price, schedule and deliverables of each engagement are set in a written proposal, invoice or agreement.").
- Fail closed: no `public.yaml` means strangers can do nothing.
- Hosted door adds: per-IP caps at the edge, a 16 KB request cap, 10 acts an hour per address. Signature checks are on (caller labeled self reported or verified: <domain>); the partner list is empty. Not yet: door-signed receipts on the hosted door, and an alert when the daily owner cap trips.

### Open source

- License MIT, same as hermes-consent-network and the six Hermes plugins.
- Repo layout: `agent_front_door/` (door, facts, server, cli, vendored consent core), `config/` (one business), `tests/`, `demo/`.
- To run a door for another business: copy `config/axiom.yaml`, point `facts_file` / `facts_url` at their facts page, set owner and booking link, write `policies/public.yaml`.
- Upstream path: propose `consent_core.py` caller-identity fields back to hermes-consent-network so the two stay one codebase; reference issue NousResearch/hermes-agent#159584.
- Not done here: publishing a package or registering in an MCP directory.

### Proof

- `uv run pytest -q`: unit tests plus one end-to-end test over a real stdio MCP connection.
- `uv run python demo/run_demo.py` writes `demo/TRANSCRIPT.md`: three fictional callers (Claude partner, Gemini stranger, GPT stranger) walk read, allowed, owner-approved, owner-declined + remembered no, and hard-floor refused paths; both receipt chains verify and agree.

### Hosted door (worker/ + owner/)

```
caller agent --MCP--> Cloudflare Worker (stateless) --RPC--> DoorState Durable Object (SQLite)
                                                                ^            |
owner's machine: afd_owner.py poll (every minute) --HTTPS out---+  pull / ack / answer / receipts
        |  sends the question to the owner's chat (Hermes send, mirror off)
        |  reads the owner's typed "consent yes|no CODE" from the local Hermes message store
        +--> pushes the answer to the door
```

- Nothing connects in to the owner's machine. The Worker makes no outbound requests.
- Owner endpoints (`/owner/pull`, `/owner/ack`, `/owner/answer`, `/owner/receipts`) need `Authorization: Bearer <token>`; the Worker holds only the token's sha256 (secret `OWNER_TOKEN_SHA256`). Without the secret the owner side stays closed.
- Decision order is the prototype's: validate, rate caps (address 10/h, caller 5/h, person 5/h), hard floor, prior answer, policy, remembered no (90 days, similarity 0.6), open questions per caller (2), daily owner cap (10, questions and leads together, owner's time zone), then one question.
- A yes to `request_call` returns exactly: "Recorded for Deploy Axiom. If the work fits, P. K. Stewart takes the call. To pick a time now: <booking link from the facts page>". A yes is carried out once; later checks return `already_done`.
- Receipts: the door's chain lives in the Durable Object (`hash = sha256(prev + "\n" + canonical JSON)`); the caller gets its copy in every answer; `GET /receipts/head` shows the head publicly; the owner's machine keeps its own chain whose entries point at the door's receipt hashes, and `afd_owner.py receipts --verify` checks both chains and that they agree.
- Owner chat answers are accepted only from the configured owner user id on the configured platform, only for codes this machine sent, and only from a line that is the whole answer (so a quoted message cannot answer).
- Caller words are kept for the decline memory window (90 days), then cleared.
- Tests: `worker/test/act_e2e.py` (fictional callers: waiting, yes, no, remembered no, floor, page answer, lead, daily cap, both receipt chains), `worker/test/outside_client.py` (read path against the live page, from outside).
