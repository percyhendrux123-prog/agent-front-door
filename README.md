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

**Receipts.** Every decision is written to a tamper-evident log (each line carries the fingerprint of the one before). The calling agent gets its own copy in every answer, so both sides can prove what happened.

**Fixed rule.** The door never runs on a machine that holds anything private. Run it on its own small box or container that holds only the public facts page and its own config.

What this repo is not: it is a working prototype with tests and a demo. It does not host a door anywhere, and it sends no email or text, books nothing and takes no money. The demo uses fictional people only.

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

Run a door for another business: copy `config/axiom.yaml`, point it at that business's facts page, set the owner, and write `config/policies/public.yaml`.

## More

- Full design and the technical mapping: [SPEC.md](SPEC.md)
- Demo run, three fictional callers: [demo/TRANSCRIPT.md](demo/TRANSCRIPT.md)
- Undo: [UNDO.md](UNDO.md)
- Built on [hermes-consent-network](https://github.com/percyhendrux123-prog/hermes-consent-network) (agent-to-agent consent rules for Hermes).
- Related discussion: [NousResearch/hermes-agent#159584](https://github.com/NousResearch/hermes-agent/issues/159584)

## License

MIT. See [LICENSE](LICENSE).
