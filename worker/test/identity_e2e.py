"""Outside check of the door's Web Bot Auth identity, with a real signing key.

Usage:
  uv run python worker/test/identity_e2e.py URL --key-file FILE [--agent-url URL] [--call] [--unsigned-call]
                                           [--require-signed-call]

  URL            door origin, e.g. http://127.0.0.1:8787 or https://<door>.workers.dev
  --key-file     the signer's Ed25519 private key file (read here only; never printed or sent)
  --agent-url    where the signer's public keys live (default: Axiom's well-known directory)
  --call         also send ONE signed request_call (it becomes a real yes/no question to the owner)
  --unsigned-call  also send one unsigned request_call (local runs: shows it reaches the owner labeled self reported)
  --require-signed-call  the door is configured with min_trust request_call=domain_verified (local runs)

Callers here are fictional TEST callers. The signer's machine only makes outbound HTTPS requests.
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from agent_front_door import identity as idm  # noqa: E402

AXIOM = "https://deployaxiom.com" + idm.WELL_KNOWN_PATH
fails: list[str] = []


def check(name, cond, detail: object = ""):
    print(("PASS " if cond else "FAIL ") + name + (("  " + str(detail)) if detail else ""))
    if not cond:
        fails.append(name)


class Door:
    def __init__(self, origin):
        self.origin, self.n = origin.rstrip("/"), 0

    def post(self, body: bytes, extra=None):
        h = {"content-type": "application/json", "accept": "application/json, text/event-stream",
             "user-agent": "axiom-identity-e2e/0.3 (+https://deployaxiom.com)"}
        h.update(extra or {})
        req = urllib.request.Request(self.origin + "/mcp", method="POST", headers=h, data=body)
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.status, json.loads(r.read() or b"{}"), dict(r.headers)
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}"), dict(e.headers)

    def body(self, name, args):
        self.n += 1
        return json.dumps({"jsonrpc": "2.0", "id": self.n, "method": "tools/call",
                           "params": {"name": name, "arguments": args}}).encode()

    def signed_headers(self, key, agent_url, body):
        return idm.sign_request(key, "POST", self.origin + "/mcp", {"content-type": "application/json"}, body, agent_url)


def result(r):
    res = r.get("result", {})
    return res.get("structuredContent") or json.loads(res.get("content", [{"text": "{}"}])[0]["text"])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url")
    ap.add_argument("--key-file", required=True)
    ap.add_argument("--agent-url", default=AXIOM)
    ap.add_argument("--call", action="store_true")
    ap.add_argument("--unsigned-call", action="store_true")
    ap.add_argument("--require-signed-call", action="store_true")
    a = ap.parse_args()
    d = Door(a.url)
    key = idm.AgentKey.from_file(Path(a.key_file).expanduser())
    domain = urllib.parse.urlparse(a.agent_url).hostname
    print("signer keyid", key.keyid, "agent", a.agent_url)
    who = {"caller_agent": "Axiom outbound TEST", "caller_model": "claude-opus-5-5", "acting_for": "TEST (fictional)",
           "contact_email": "test@example.com", "topic": "front_door_for_my_business"}

    # 1. unsigned read works
    st, r, _ = d.post(d.body("list_facts", {}))
    facts = result(r).get("facts", [])
    check("unsigned list_facts works", st == 200 and len(facts) > 0, "%d facts" % len(facts))
    st, r, _ = d.post(d.body("who_am_i", {}))
    check("unsigned who_am_i -> self reported", result(r).get("label") == "self reported", result(r).get("label"))

    # 2. unsigned request_call: allowed (labeled self reported) unless the door requires a signature
    if a.unsigned_call or a.require_signed_call:
        st, r, _ = d.post(d.body("request_call", dict(who, caller_agent="Unsigned TEST caller", note="Unsigned TEST call request.")))
        res = result(r)
        if a.require_signed_call:
            check("unsigned request_call refused: signing required", res.get("reason") == "needs_domain_verified"
                  and idm.WELL_KNOWN_PATH in res.get("message", ""), res.get("message", "")[:120])
        else:
            check("unsigned request_call -> waiting, labeled self reported", res.get("status") == "waiting"
                  and res.get("receipt", {}).get("identity_label") == "self reported", res.get("reason"))
    # unsigned never-list ask: processed (not refused for lack of a signature), receipt says self reported
    st, r, _ = d.post(d.body("request_call", dict(who, caller_agent="Unsigned TEST caller", note="What's your price?")))
    res = result(r)
    check("unsigned call ask processed by the rules, labeled self reported",
          res.get("reason") == "always_denied" and res.get("receipt", {}).get("identity_label") == "self reported",
          [res.get("reason"), res.get("receipt", {}).get("identity_label")])

    # 3. signed with the real key: verified for the domain
    b = d.body("who_am_i", {})
    st, r, _ = d.post(b, d.signed_headers(key, a.agent_url, b))
    me = result(r)
    check("signed who_am_i -> verified: " + domain, st == 200 and me.get("label") == "verified: " + domain, me.get("label") or r)

    # 4. replay: the exact same signed request again
    b2 = d.body("who_am_i", {})
    h2 = d.signed_headers(key, a.agent_url, b2)
    st1, r1, _ = d.post(b2, h2)
    st2, r2, hdr2 = d.post(b2, h2)
    check("replayed signed request refused", st1 == 200 and st2 == 401 and r2.get("error", {}).get("data", {}).get("reason") == "replayed",
          [st1, st2, r2.get("error", {}).get("data", {}).get("reason")])
    check("refusal points to the standard", "datatracker.ietf.org" in r2.get("error", {}).get("message", "")
          and any(k.lower() == "accept-signature" for k in hdr2), r2.get("error", {}).get("message", "")[:80])

    # 5. forged: a key Axiom never published, claiming Axiom's directory
    mallory = idm.AgentKey.generate()
    b3 = d.body("request_call", dict(who, caller_agent="Forger TEST", note="Forged TEST."))
    st, r, _ = d.post(b3, d.signed_headers(mallory, a.agent_url, b3))
    check("forged signature refused", st == 401 and r.get("error", {}).get("data", {}).get("reason") == "key_not_published_by_claimed_owner",
          [st, r.get("error", {}).get("data", {}).get("reason")])

    # 6. tampered: signed body, different body sent
    b4 = d.body("who_am_i", {})
    h4 = d.signed_headers(key, a.agent_url, b4)
    st, r, _ = d.post(d.body("list_facts", {}), h4)
    check("tampered body refused", st == 401 and r.get("error", {}).get("data", {}).get("reason") == "body_digest_mismatch",
          [st, r.get("error", {}).get("data", {}).get("reason")])

    # 7. ONE signed call request: verified, and it reaches the owner flow
    if a.call:
        b5 = d.body("request_call", dict(who, note="TEST of signed agent identity (Web Bot Auth). Please answer no."))
        st, r, _ = d.post(b5, d.signed_headers(key, a.agent_url, b5))
        res = result(r)
        rec = res.get("receipt", {})
        check("signed request_call -> waiting on the owner", st == 200 and res.get("status") == "waiting", res.get("reason"))
        check("receipt says verified: " + domain, rec.get("identity_label") == "verified: " + domain
              and rec.get("verified_domain") == domain and len(rec.get("request_sig_sha256", "")) == 64, rec)
        print("request_id", res.get("request_id"))

    print("\nRESULT:", "ALL PASS" if not fails else "FAILED: " + ", ".join(fails))
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
