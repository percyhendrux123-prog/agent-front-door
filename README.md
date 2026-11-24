# agent-front-door

A front door for AI agents, with the owner's consent on every action.

More visits to a business now come from someone's assistant (Claude, ChatGPT, Gemini, another Hermes) sent to find a firm and set up a call. This is the one place those agents can knock. It speaks MCP, the plug the major assistants already use, so it works with any model.

**What a visiting agent can do (4 paths)**

1. **Allowed:** an ask on the owner's allowed list goes through (for example, leaving a lead).
2. **Ask the owner:** anything else becomes one yes/no question to the owner. Nothing happens until the owner answers.
3. **Remembered no:** if the owner said no before, the ask is refused and the owner is not asked again.
4. **Never:** some asks are refused every time, for everyone.

Reading is always open: the business's facts come straight off its own facts page, word for word. The door cannot say anything the page does not say.

**The never-list.** Prices, payments and refunds. Deleting data. Sending messages to anyone else. Client data or passwords. Commitments in the owner's name.

**Who is calling.** Agents can sign their requests with the open Web Bot Auth standard (the agent's key published on its owner's domain). A verified caller is shown to the owner as "verified: their-domain.com"; an unsigned one as "self reported". Both can read, leave a message, ask a question or ask for a call, under the same caps and never-list. A signature that fails (forged, replayed, tampered) is refused. It proves which domain stands behind an agent, not that its owner is honest. The hosted door checks signatures live; Deploy Axiom's own agents sign with the key at https://deployaxiom.com/.well-known/http-message-signatures-directory. See [docs/IDENTITY-ONE-PAGER.md](docs/IDENTITY-ONE-PAGER.md).

**Receipts.** Every decision is written to a tamper-evident log (each line carries the fingerprint of the one before). The calling agent gets its own copy in every answer, so both sides can prove what happened.

**Fixed rule.** The door never runs on a machine that holds anything private. Run it on its own small box or container that holds only the public facts page and its own config.

**Hosted door (Cloudflare Workers Free).** `worker/` is the same door as one Cloudflare Worker plus one SQLite Durable Object, on the free plan only. Deploy Axiom runs it at `https://axiom-front-door.percyhendrux123.workers.dev/mcp`. Read tools answer from the bundled facts page; `request_call`, `ask_question` and `leave_lead` go through the same rules, and `check_request` collects the owner's answer.

**The owner's machine is never opened to the internet.** The door never sends anything and never connects in. `owner/afd_owner.py` runs on the owner's machine and only connects out: every minute it pulls new questions from the door, sends each one to the owner's chat, reads the owner's typed `consent yes CODE` / `consent no CODE`, and pushes the answer back. The owner side is locked with a token whose hash is the only thing the Worker holds.

**Caller words never reach a model.** A note is cut to 280 characters with links removed and shown only to the owner as "their words, unverified". The chat message is sent without a copy in any agent's session, and the owner is asked to type the answer as a new message so a quote never carries the words back in.

**Caps.** At most 10 owner questions or leads a day across all callers; 2 open questions per caller; 5 acts an hour per caller and per person; 10 an hour per address; plus per-address and whole-door request limits at the edge. Over any free-plan limit the door fails closed; it never bills.

What this repo is not: it sends no email or text to callers, books nothing and takes no money. A yes to a call request returns the booking link; the person picks the time. Tests and demos use fictional people only.

---

## Install and run

Needs Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```sh
git clone https://github.com/percyhendrux123-prog/agent-front-door
cd agent-front-door
uv sync
uv run pytest -q                    # tests, including a real stdio MCP round trip
uv run python demo/run_demo.py      # regenerates demo/TRANSCRIPT.md
uv run afd-server                   # stdio server (Claude Desktop / Hermes / Gemini CLI config)
uv run afd-server --http            # streamable HTTP on 127.0.0.1:8765/mcp
uv run afd owner-inbox              # owner: open questions
uv run afd yes CODE                 # owner: approve
uv run afd no CODE                  # owner: decline (remembered)
uv run afd receipts --verify        # check the receipt chain
```

Hosted door and owner side (see [worker/DEPLOY.md](worker/DEPLOY.md)):

```sh
uv run python worker/build_facts.py                     # bundle the LIVE facts page (sha256 recorded)
cd worker && npx wrangler deploy                        # Workers Free; one SQLite Durable Object
python3 -c "import hashlib,sys;print(hashlib.sha256(open(sys.argv[1]).read().strip().encode()).hexdigest())" TOKEN_FILE \
  | npx wrangler secret put OWNER_TOKEN_SHA256           # only the token's hash goes to the Worker
cd .. && uv run python worker/test/outside_client.py https://<door>/mcp        # read path from outside
python3 worker/test/act_e2e.py http://127.0.0.1:8787 --token-file T --owner-sim --cap   # act path, local
AFD_DOOR_URL=https://<door> AFD_TOKEN_FILE=T AFD_OWNER_CHAT_USER=<id> python3 owner/afd_owner.py poll
python3 owner/afd_owner.py receipts --verify            # door chain, owner chain, both sides agree
```

Callers: send a real `User-Agent` header. Cloudflare in front of the hosted door returns HTTP 403 to requests without one (for example Python `urllib` defaults); curl and normal MCP clients are fine. A `check_request` answer is delivered once; don't expect the first-time message on a repeat check.

Run a door for another business: copy `config/axiom.yaml`, point it at that business's facts page, set the owner, and write `config/policies/public.yaml`.

## More

- Full design and the technical mapping: [SPEC.md](SPEC.md)
- Demo run, three fictional callers: [demo/TRANSCRIPT.md](demo/TRANSCRIPT.md)
- Undo: [UNDO.md](UNDO.md)
- Built on [hermes-consent-network](https://github.com/percyhendrux123-prog/hermes-consent-network) (agent-to-agent consent rules for Hermes).
- Related discussion: [NousResearch/hermes-agent#159584](https://github.com/NousResearch/hermes-agent/issues/159584)

## License

MIT. See [LICENSE](LICENSE).
