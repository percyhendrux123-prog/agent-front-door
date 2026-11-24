"""Write worker/test/identity_vectors.json: requests signed by the Python reference (identity.py), with the
reason the Python verifier gives each one. identity_vectors.mjs checks the Worker's port gives the same
reasons. Fictional domains, throwaway keys; only public keys and signatures are written, never a private key.

    uv run python worker/test/make_identity_vectors.py
"""
import json
from pathlib import Path

from agent_front_door import identity as idm

DOOR = "door.axiom-test.example"
NOW = 1_795_540_000
OUT = Path(__file__).with_name("identity_vectors.json")


def main() -> None:
    carol, mallory, other = idm.AgentKey.generate(), idm.AgentKey.generate(), idm.AgentKey.generate()
    carol_url = idm.well_known_url("carol-agent.example")
    pages = {
        carol_url: idm.directory([carol], {"client_name": "Carol's assistant", "acts_for": "Carol Diaz (fictional)"}),
        "https://keys.signer.example/agents/carol.json": idm.directory([other]),
        idm.well_known_url("unsigned-file.example"): idm.directory([carol]),
    }
    signers = {carol_url: ("carol-agent.example", [carol]),
               "https://keys.signer.example/agents/carol.json": ("keys.signer.example", [other])}
    # each directory response carries its own signature (tag http-message-signatures-directory), except one
    resp_headers = {u: {k.lower(): v for k, v in idm.sign_directory_response(ks, host, now=NOW - 10).items()}
                    for u, (host, ks) in signers.items()}
    resp_headers[idm.well_known_url("unsigned-file.example")] = {}

    def fetch(url):
        if url in pages:
            return 200, dict({"content-type": idm.DIRECTORY_MEDIA_TYPE}, **resp_headers[url]), json.dumps(pages[url]).encode()
        return 404, {}, b""

    cases = []

    def add(name, key, agent_url, body=b'{"jsonrpc":"2.0","id":1,"method":"tools/call"}', path="/mcp", now=NOW,
            mutate=None, check_body=None, check_path=None, **kw):
        url = "https://%s%s" % (DOOR, path)
        h = {"content-type": "application/json"}
        h.update(idm.sign_request(key, "POST", url, h, body, agent_url, now=now, **kw))
        if mutate:
            mutate(h)
        cb = body if check_body is None else check_body
        cp = path if check_path is None else check_path
        v = idm.Verifier(DOOR, fetch=fetch, clock=lambda: NOW)
        ident = v.verify("POST", cp, h, cb)
        cases.append({"name": name, "path": cp, "headers": h, "body": cb.decode(), "level": ident.level,
                      "reason": ident.reason.split(":")[0], "rejected": ident.rejected, "domain": ident.domain,
                      "label": ident.label})

    add("verified", carol, carol_url)
    add("verified_with_query", carol, carol_url, path="/mcp?x=1")
    add("signed_no_domain", other, "https://keys.signer.example/agents/carol.json")
    add("forged_key_claims_carol", mallory, carol_url)
    add("body_swapped", carol, carol_url, check_body=b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}')
    add("path_swapped", carol, carol_url, check_path="/owner/pull")
    add("expired", carol, carol_url, now=NOW - 400)
    add("lifetime_too_long", carol, carol_url, ttl=3600)
    add("created_in_future", carol, carol_url, now=NOW + 300)
    add("short_nonce", carol, carol_url, nonce="abc")
    add("http_agent_url", carol, "http://carol-agent.example" + idm.WELL_KNOWN_PATH)
    add("ip_agent_url", carol, "https://10.0.0.1" + idm.WELL_KNOWN_PATH)
    add("unreachable_directory", carol, idm.well_known_url("nobody-home.example"))
    add("directory_response_unsigned", carol, idm.well_known_url("unsigned-file.example"))

    def strip_tag(h):
        h["Signature-Input"] = h["Signature-Input"].replace(';tag="web-bot-auth"', "")
    add("no_tag", carol, carol_url, mutate=strip_tag)

    doc = {"door": DOOR, "now": NOW, "directories": pages, "directory_headers": resp_headers, "cases": cases}
    OUT.write_text(json.dumps(doc, indent=1) + "\n")
    print("wrote %d cases to %s" % (len(cases), OUT))
    for c in cases:
        print("  %-26s %-16s %s" % (c["name"], c["level"], c["reason"]))


if __name__ == "__main__":
    main()
