# Agent identity: research notes (A617, 2026-11-24)

Question: when an AI agent knocks on our door, how do we know who it is and which owner stands behind it? Is there a standard to build on, or do we invent one?

Short answer: there is a standard, and it is the right base. **Web Bot Auth** (IETF working group draft, authored at Cloudflare and Google) is HTTP Message Signatures (RFC 9421) plus a key directory at a reserved well-known URL on the owner's domain. That is almost exactly AXIOM's starting design (DKIM for agents), already adopted by Cloudflare, AWS and others. We adopted it as is and did not invent a format. What the standard deliberately leaves out is the part we care about: what a verified identity is *allowed to do*, and proof for both sides of what happened. That is what ours adds.

Time-boxed (about 30 minutes). Sources read on 2026-11-24 unless noted.

## What exists

| Work | Status / date | What it does | Fit for us |
|---|---|---|---|
| RFC 9421 HTTP Message Signatures | RFC, Feb 2024. https://www.rfc-editor.org/rfc/rfc9421 | How to sign parts of an HTTP request (method, path, headers) with Ed25519 etc. | The signing format. Our code reproduces its Ed25519 test vector (B.2.6) byte for byte. |
| draft-ietf-webbotauth-httpsig-protocol-01 ("Web Bot Auth") | WG draft, 2026-10-29, Cloudflare + Google. https://datatracker.ietf.org/doc/draft-ietf-webbotauth-httpsig-protocol/ | `Signature-Agent` header names the URL of the agent's keys; keys are a JWK Set; at `/.well-known/http-message-signatures-directory` the **domain operator stands behind the key set** (section 4.5); `keyid` = key thumbprint; `tag="web-bot-auth"`. | Adopted. Our code verifies the draft's own Ed25519 test vector (E.2.1). |
| Same draft, section 4.1 / 4.6 | | States plainly: a valid signature "says nothing about who operates the Agent, whether the Agent is benign, or whether the request is authorized. Those are origin policy." Authorization, delegation, consent: out of scope. | This is the gap we fill. |
| IETF 127 slides | 2026-11, San Francisco. https://datatracker.ietf.org/meeting/127/materials/slides-127-webbotauth-http-message-signatures-for-automated-traffic-00 | "Identity is the Signature-Agent URL; key rotation keeps the same URL." Signing is voluntary; origins can ask with `Accept-Signature`. | We send `Accept-Signature` on a 401. |
| draft-meunier-webbotauth-registry-04 (Signature Agent Card) | Individual draft, 2026-10-27 (Cloudflare, Amazon). https://datatracker.ietf.org/doc/html/draft-meunier-webbotauth-registry-04 | A JSON card describing the agent (name, contacts, purpose, keys), reusing OAuth client-metadata fields (CIMD). | We reuse its field names (`client_name`, `client_uri`, `contacts`) for display only, plus one field of our own, `acts_for`. |
| Other webbotauth WG drafts | https://datatracker.ietf.org/wg/webbotauth/documents/ (list read 2026-11-24) | Signed-Agent-Metadata header for per-customer sub-identities on shared platforms (2026-11-02); Reporting verification outcomes (2026-11-21, new); PACE capability management for agents (2026-11-15, new); anonymous bot auth (2026-07-19). | Not read in full. "Reporting verification outcomes" and PACE may overlap with our receipts and trust levels; read before proposing anything upstream. |
| Cloudflare Verified Bots / signed agents | Docs updated 2026-11-12. https://developers.cloudflare.com/bots/concepts/bot/verified-bots/ | Web Bot Auth signature is one accepted proof of honest self-identification; "signed agents are now Verified" as of 2026-07-01. | Our Workers host already sits behind this. |
| Adoption | WorkOS, 2026-10-19. https://workos.com/blog/web-bot-auth-identify-ai-agents | Cloudflare and AWS verify it on live traffic; first signed-agent cohort: ChatGPT agent, Goose (Block), Browserbase, Anchor Browser; Vercel, Shopify, Visa implemented. | Real adoption, so building on it is not a bet on a paper. |
| Adoption gap | Arkose Labs Q3 2026 data, via a 2026-11-21 write-up (secondary source, not checked against the original report). https://thehackernewsexperts.blogspot.com/2026/11/ai-agents-at-login-distinguishing.html | Only about 2.3% of legitimate agent sessions carried a verified signature; ChatGPT agent signed 78.4% of its own. | Most callers will arrive unsigned for a while, so the door must stay useful to them (read, leave a message). |
| Cloudflare Connect 2026, Experian session | https://www.cloudflare.com/connect/2026/session/ready-for-shopping-season-verifying-and-authorizing-buying-agents/ | "Web Bot Auth answers one [question]: did this key send this request unmodified?" The rest (human bound, cart approved) is a separate "know your agent" layer. | Same split as ours: identity first, then the owner's rules decide. |
| A2A v1.0 signed Agent Cards | Schema reviewed against A2A 1.0.1 on 2026-10-21. https://www.agentcard.net/agent-card-schema ; https://www.getmaxim.ai/articles/a2a-agent-card/ (2026-10-28) | JWS signature over the canonicalized agent card (the discovery document). | Signs the *card*, not each request. Complementary; nothing to replace. |
| MCP authorization, spec 2026-07-28 | https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization ; Auth0, 2026-11-23 | OAuth 2.1; Client ID Metadata Documents (an HTTPS URL as client id) preferred, Dynamic Client Registration deprecated. | Answers a different question: a user letting a client into *their account*. The door has no accounts, so we don't need OAuth. CIMD and the Signature Agent Card share the same field namespace, which keeps us compatible. |
| Cloudflare + GoDaddy, Agent Name Service | Press release 2026-04-07. https://www.cloudflare.com/press/press-releases/2026/cloudflare-and-godaddy-partner-to-help-enable-an-open-agentic-web/ | Name service for agents, alongside Web Bot Auth. | Not evaluated. |

## Where AXIOM's starting design changed

| Starting design | What we built instead, and why |
|---|---|
| Our own file at `/.well-known/agent-identity.json` | The registered `/.well-known/http-message-signatures-directory` (JWK Set). Same idea, already standard and already checked by Cloudflare and AWS. |
| Ed25519 over method + path + body hash + timestamp + nonce, our own layout | RFC 9421 signature over `@method`, `@authority`, `@path`, `Content-Digest` (RFC 9530 body hash), `Signature-Agent`, with `created`, `expires`, `nonce`, `tag="web-bot-auth"`. Same contents, standard layout, proven against two published test vectors. |
| A revocation list in the file | The draft's model: the owner removes the key from the directory (keys may also carry `exp`). Doors re-check at least every 5 minutes, whatever cache time the publisher asks for. The door's owner can also revoke a key or a whole agent URL locally. |
| "Who it acts for, contact" in the file | Signature Agent Card fields (`client_name`, `contacts`) plus `acts_for`. Shown to the owner as the domain's own claim, and no permission depends on it. |
| Owner-issued partner key (a shared secret) | A partner is now a **verified domain the owner lists by name** (`policies/partners/<x>.yaml` with `domain:`). No secret to hand out or leak. The old shared-key path still works, for compatibility. |

## What is ours (not in any draft we read)

1. **Trust levels the consent rules use.** unsigned < signed (a key, but no domain) < domain_verified < partner. Each action can require a level (`identity.min_trust` in the door; `require_partner` / `require_domain_verified` in consent-network peer files). Axiom's door (owner's rule, 11-24): every caller may read, leave a lead, ask a question or ask for a call; the owner's question says "self reported" or "verified: <domain>"; partners get their own allow-list (none listed yet).
2. **The verified domain is the principal.** Rate caps, open questions and remembered no's attach to the domain, not to the name the agent types. A domain can't get around an owner's no by renaming its agent.
3. **Two-sided, signed receipts.** The door's receipt records the hash of the caller's signature. The door signs the receipt it hands back with its own published key. Each side holds the other's signature over the same event.
4. **A stricter profile than the draft's minimum.** The draft only requires `@authority`. We require method, path, body and a single-use nonce, and lifetimes of 5 minutes (the draft allows up to 24 hours), so a captured request can't be replayed or turned into a different ask.

Possible overlap to check before any upstream proposal: draft-suresh-webbotauth-verification-outcome (receipts / reporting) and draft-meunier-webbotauth-capacity-management (PACE, capabilities).
