# Agent Front Door: spec

Status: open-source prototype (MIT). Not hosted anywhere by this repo. Owner of every go-live decision: the business owner.

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
| one question to owner | `OwnerChannel`; prototype writes `.state/owner_channel.jsonl`, production uses `hermes send -t telegram`. Owner replies `consent yes CODE` / `consent no CODE` (prototype: `afd yes CODE`) |
| remembered no | `Declines`, keyed by caller agent + person, 90 days, similarity 0.6 |
| `max_pending` | per caller (public: 2) |
| receipts | `Receipts` hash chain in `.state/receipts.jsonl`; each answer returns `{seq, ts, ask_id, ask_type, decision, reason, text_sha256, prev, hash}` so the caller keeps its own chain; `compare_sides` cross-checks |

Decision order for every act: validate labels and email, rate cap, hard floor, prior owner answer for this exact ask, policy (deny / allow), remembered no, pending cap, daily owner cap, then one owner question.

Identity is **self-reported** unless a partner key matches. Self-reported names are recorded and shown to the owner as such; they never unlock an allow-list.

### Abuse limits

- Rate caps: 60 reads per minute per caller; 5 acts per hour per caller agent and per person acted for; 2 open owner questions per public caller; 10 owner questions per day across everyone. All in `config/axiom.yaml`.
- Free text: notes capped at 280 characters; links, control characters and bidi overrides removed; labels limited to 64 plain characters. Caller text is never passed to any model, only stored for the owner and shown as "their words, unverified".
- Floor words: price, payment, refund, deletion, sends to others, client data or credentials, commitments. A hit is refused before policy, for partners too, and the reply quotes the page (for price: "The scope, price, schedule and deliverables of each engagement are set in a written proposal, invoice or agreement.").
- Fail closed: no `public.yaml` means strangers can do nothing.
- Production adds (not in the prototype): per-IP caps at the edge (Netlify/Cloudflare), request size limit, partner keys issued and revoked by the owner, and an alert when the daily owner cap trips.

### Open source

- License MIT, same as hermes-consent-network and the six Hermes plugins.
- Repo layout: `agent_front_door/` (door, facts, server, cli, vendored consent core), `config/` (one business), `tests/`, `demo/`.
- To run a door for another business: copy `config/axiom.yaml`, point `facts_file` / `facts_url` at their facts page, set owner and booking link, write `policies/public.yaml`.
- Upstream path: propose `consent_core.py` caller-identity fields back to hermes-consent-network so the two stay one codebase; reference issue NousResearch/hermes-agent#159584.
- Not done here: publishing a package, hosting a door, or registering in an MCP directory.

### Proof

- `uv run pytest -q`: unit tests plus one end-to-end test over a real stdio MCP connection.
- `uv run python demo/run_demo.py` writes `demo/TRANSCRIPT.md`: three fictional callers (Claude partner, Gemini stranger, GPT stranger) walk read, allowed, owner-approved, owner-declined + remembered no, and hard-floor refused paths; both receipt chains verify and agree.
