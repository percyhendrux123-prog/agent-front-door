# Who is this agent, and who does it speak for? (one page)

**The problem.** Any agent can type "I'm Carol's assistant." Today the door has to take its word, and so does every other business. Email had the same problem, and fixed it by letting a domain publish a key that signs its mail. This does the same thing for agents.

**How it works.**
1. Carol's company owns carol-agent.example. It publishes its agent's public key on that domain, at a fixed address every door knows to check.
2. Carol's agent signs every request it sends. The signature covers what it is asking for, a timestamp, and a one-time number.
3. Our door fetches the key from carol-agent.example and checks the signature. If it matches, the receipt says **"verified: carol-agent.example"**. If not, the request is refused before it reaches anything.

We did not invent the format. It is the open standard Cloudflare and Google are writing at the IETF (Web Bot Auth). Cloudflare and AWS already check it, and ChatGPT's agent already signs with it. Our code passes that standard's own published test cases.

**What it proves.** That the owner of a named domain stands behind this agent, and that the request was not changed or replayed on the way.

**What it does not prove.** That the person or business behind the domain is honest. That the agent is right. That anyone should get what they ask for. A scammer can buy a domain and sign perfectly. That is why the owner's rules still decide every ask, and why the hard floor stays: no prices, payments, deletions, client data, or commitments, for anyone.

**What each level can do at Axiom's door.**

| Who is calling | What they can do |
|---|---|
| Unsigned (most agents today) | Read the facts page, leave a message, ask a question, ask for a call. The owner's question says "self reported". |
| Signed by a domain that publishes its key | The same, and the owner's question says "verified: their-domain". |
| A domain the owner has listed as a partner | That partner's own list, e.g. calls go straight through. Later: calendar holds. |

**What's new in ours.** The standard stops at "this key sent this request." Ours connects that to the owner's consent rules (who can ask for what). It ties a "no" to the domain, so renaming the agent doesn't get around it. And the door signs its receipt back, so both sides can prove what happened.

**Shutting it off.** Carol's company removes its key: our door stops trusting it within 5 minutes. Our owner can also block a key or a domain on our side at any time.

**Where it stands (live, 2026-11-24).**
- Axiom's key is published: https://deployaxiom.com/.well-known/http-message-signatures-directory (one public key; the private key never leaves Axiom's machine).
- The live door checks signatures: https://axiom-front-door.percyhendrux123.workers.dev/mcp. From outside: an unsigned read works and is labeled self reported; a request signed with Axiom's real key is labeled "verified: deployaxiom.com" and reached the owner as one question; a forged key, a replay and a tampered body were each refused.
- Tests: door 60 passed (1 optional skip), the Worker's verifier 25 checks (same answers as the Python one, plus the published test vectors), consent network 62 passed. Test domains are made up.
- Next: offer it upstream, so the Hermes A2A server can run this check for every Hermes agent.
