"""Agent identity: Web Bot Auth signatures checked against the claimed owner's domain.

All domains here are fictional (.example / .test). No network: key directories come from a fake fetcher,
and the end-to-end test talks to a door on 127.0.0.1.
"""
import base64
import json
import socket
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from agent_front_door import identity as idm

ROOT = Path(__file__).resolve().parent.parent
DOOR = "door.axiom-test.example"
NOW = 1_795_540_000


class Clock:
    def __init__(self, t=NOW):
        self.t = t

    def __call__(self):
        return self.t


class Web:
    """Fake internet: URL -> (status, headers, body). Counts fetches so cache behaviour is visible.

    Directory responses are signed at fetch time (tag http-message-signatures-directory), using the
    test's clock when it has one, so they are always in date."""

    def __init__(self, now=time.time):
        self.pages, self.fetches, self.now = {}, [], now

    def publish(self, domain, keys, card=None, max_age=None, path=idm.WELL_KNOWN_PATH, sign=True):
        headers = {"content-type": idm.DIRECTORY_MEDIA_TYPE}
        if max_age is not None:
            headers["cache-control"] = "max-age=%d" % max_age
        self.pages["https://%s%s" % (domain, path)] = (200, headers, json.dumps(idm.directory(keys, card)).encode(),
                                                      (domain, list(keys)) if sign and keys else None)

    def __call__(self, url):
        self.fetches.append(url)
        if url not in self.pages:
            return 404, {}, b""
        status, headers, body, signer = self.pages[url]
        if signer:
            headers = dict(headers, **{k.lower(): v for k, v in
                                       idm.sign_directory_response(signer[1], signer[0], now=self.now() - 10).items()})
        return status, headers, body


@pytest.fixture
def env():
    clock = Clock()
    web = Web(now=clock)
    carol = idm.AgentKey.generate()
    web.publish("carol-agent.example", [carol], card={"client_name": "Carol's assistant",
                                                     "contacts": ["mailto:carol@carol-agent.example"],
                                                     "acts_for": "Carol Diaz (fictional)"})
    v = idm.Verifier(DOOR, fetch=web, clock=clock)
    return web, clock, carol, v


def signed(key, agent_url, body=b'{"tool":"request_call"}', path="/mcp", authority=DOOR, now=NOW, **kw):
    url = "https://%s%s" % (authority, path)
    h = {"content-type": "application/json"}
    h.update(idm.sign_request(key, "POST", url, h, body, agent_url, now=now, **kw))
    return h, body


def check(v, h, body, path="/mcp", method="POST"):
    return v.verify(method, path, h, body)


CAROL = idm.well_known_url("carol-agent.example")


# -- interop: our signature code against the published test vectors ---------------------------
RFC_ED25519 = {"kty": "OKP", "crv": "Ed25519", "x": "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"}


def test_jwk_thumbprint_matches_the_web_bot_auth_draft():
    assert idm.jwk_thumbprint(RFC_ED25519) == "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U"


def test_rfc9421_b26_ed25519_vector_verifies():
    msg = idm.Message("POST", "example.com", "/foo", "param=Value&Pet=dog",
                      {"date": "Tue, 20 Apr 2021 02:07:55 GMT", "content-type": "application/json",
                       "content-length": "18"})
    comps, params = idm.parse_dictionary('sig-b26=("date" "@method" "@path" "@authority" "content-type" '
                                         '"content-length");created=1618884473;keyid="test-key-ed25519"')["sig-b26"]
    base, _ = idm.signature_base(msg, [(n, list(p)) for n, p in comps], params)
    sig = base64.b64decode("wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==")
    idm.public_key_from_jwk(RFC_ED25519).verify(sig, base)  # raises if our signature base is wrong


def test_web_bot_auth_draft_e21_vector_verifies():
    msg = idm.Message("GET", "example.com", "/", "", {"signature-agent": 'sig2="https://signature-agent.test"'})
    comps, params = idm.parse_dictionary(
        'sig2=("@authority" "signature-agent";key="sig2");created=1735689600;'
        'keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=4889289600;'
        'nonce="n9p433xm+NJ3ph3upfBIGmsuwHw387YV7Q/F+6BSpGCVjYCqQw6rznNA8PVVLySrAWsv0hQtFioQb6E1YsauiA==";'
        'tag="web-bot-auth"')["sig2"]
    base, _ = idm.signature_base(msg, [(n, list(p)) for n, p in comps], params)
    sig = base64.b64decode("CGokAoY/FrPpyuzTe1Fb2kLTAH9Idw6qSFd1+D77r1firsMRCxeuLu5e6O+ek3zQgDMAzjiXtLVfqE00xnABCQ==")
    idm.public_key_from_jwk(RFC_ED25519).verify(sig, base)


# -- the happy path ---------------------------------------------------------------------------
def test_signed_by_a_key_the_domain_publishes_is_domain_verified(env):
    web, clock, carol, v = env
    ident = check(v, *signed(carol, CAROL))
    assert (ident.level, ident.reason, ident.rejected) == (idm.DOMAIN_VERIFIED, "ok", False)
    assert ident.domain == "carol-agent.example" and ident.label == "verified: carol-agent.example"
    assert ident.card["acts_for"] == "Carol Diaz (fictional)"
    assert len(ident.signature_sha256) == 64


def test_no_signature_is_unsigned_not_rejected(env):
    *_, v = env
    ident = v.verify("POST", "/mcp", {"content-type": "application/json"}, b"{}")
    assert (ident.level, ident.rejected, ident.label) == (idm.UNSIGNED, False, "self reported")


def test_key_at_a_non_well_known_url_is_signed_but_names_no_domain(env):
    web, clock, carol, v = env
    web.publish("hosting.example", [carol], path="/users/carol/keys.json")
    ident = check(v, *signed(carol, "https://hosting.example/users/carol/keys.json"))
    assert ident.level == idm.SIGNED and ident.domain == "" and not ident.rejected


def test_partner_domain_is_recognised(env):
    web, clock, carol, _ = env
    v = idm.Verifier(DOOR, fetch=web, clock=clock, partners={"carol-agent.example": "carol"})
    assert check(v, *signed(carol, CAROL)).level == idm.PARTNER


# -- forged key, wrong domain -----------------------------------------------------------------
def test_forged_key_claiming_someone_elses_domain_is_rejected(env):
    web, clock, carol, v = env
    mallory = idm.AgentKey.generate()           # not in carol-agent.example's directory
    ident = check(v, *signed(mallory, CAROL))
    assert ident.rejected and ident.reason == "key_not_published_by_claimed_owner"
    assert ident.level == idm.UNSIGNED


def test_swapping_signature_agent_to_another_domain_breaks_the_signature(env):
    web, clock, carol, v = env
    mallory = idm.AgentKey.generate()
    web.publish("mallory.example", [mallory])
    h, body = signed(mallory, idm.well_known_url("mallory.example"))
    h["Signature-Agent"] = 'sig1="%s"' % CAROL       # claim carol after signing
    ident = check(v, h, body)
    assert ident.rejected and ident.reason in ("key_not_published_by_claimed_owner", "bad_signature")


def test_signature_made_for_another_door_does_not_work_here(env):
    web, clock, carol, v = env
    h, body = signed(carol, CAROL, authority="other-door.example")
    ident = check(v, h, body)
    assert ident.rejected and ident.reason == "bad_signature"


def test_tampered_body_is_rejected(env):
    web, clock, carol, v = env
    h, body = signed(carol, CAROL, body=b'{"tool":"leave_lead"}')
    assert check(v, h, b'{"tool":"request_call"}').reason == "body_digest_mismatch"
    h["Content-Digest"] = idm.content_digest(b'{"tool":"request_call"}')   # fix the digest too
    assert check(v, h, b'{"tool":"request_call"}').reason == "bad_signature"


# -- replay and time --------------------------------------------------------------------------
def test_replayed_request_is_rejected(env):
    web, clock, carol, v = env
    h, body = signed(carol, CAROL)
    assert check(v, h, body).level == idm.DOMAIN_VERIFIED
    again = check(v, h, body)
    assert again.rejected and again.reason == "replayed"


def test_expired_signature_is_rejected(env):
    web, clock, carol, v = env
    h, body = signed(carol, CAROL, ttl=60)
    clock.t = NOW + 60 + 61          # past expires plus the 60 s skew allowance
    ident = check(v, h, body)
    assert ident.rejected and ident.reason == "expired"


def test_signature_from_the_future_is_rejected(env):
    web, clock, carol, v = env
    ident = check(v, *signed(carol, CAROL, now=NOW + 600))
    assert ident.rejected and ident.reason == "created_in_future"


def test_long_lived_signature_is_refused(env):
    web, clock, carol, v = env
    ident = check(v, *signed(carol, CAROL, ttl=24 * 3600))   # the draft allows a day; we allow 5 minutes
    assert ident.rejected and ident.reason == "lifetime_too_long"


def test_signature_without_nonce_or_body_coverage_is_refused(env):
    web, clock, carol, v = env
    h, body = signed(carol, CAROL)
    h["Signature-Input"] = h["Signature-Input"].replace(' "content-digest"', "")
    assert check(v, h, body).reason == "body_not_covered"


# -- revocation and freshness -----------------------------------------------------------------
def test_removing_the_key_from_the_domain_revokes_it_within_the_cache_window(env):
    web, clock, carol, v = env
    assert check(v, *signed(carol, CAROL)).level == idm.DOMAIN_VERIFIED
    web.publish("carol-agent.example", [])      # owner pulls the key
    clock.t = NOW + 100                          # inside the 5-minute cache: still trusted (documented window)
    assert check(v, *signed(carol, CAROL, now=clock.t)).level == idm.DOMAIN_VERIFIED
    clock.t = NOW + 301                          # cache expired: re-fetched, key gone
    ident = check(v, *signed(carol, CAROL, now=clock.t))
    assert ident.rejected and ident.reason == "key_not_published_by_claimed_owner"


def test_publisher_max_age_cannot_stretch_the_cache(env):
    web, clock, carol, v = env
    web.publish("carol-agent.example", [carol], max_age=86400)
    check(v, *signed(carol, CAROL))
    web.publish("carol-agent.example", [])
    clock.t = NOW + 301
    assert check(v, *signed(carol, CAROL, now=clock.t)).reason == "key_not_published_by_claimed_owner"


def test_door_owner_can_revoke_a_key_or_an_agent_locally(env):
    web, clock, carol, _ = env
    v1 = idm.Verifier(DOOR, fetch=web, clock=clock, revoked_keyids=[carol.keyid])
    v2 = idm.Verifier(DOOR, fetch=web, clock=clock, revoked_agents=[CAROL])
    assert check(v1, *signed(carol, CAROL)).reason == "revoked_by_door"
    assert check(v2, *signed(carol, CAROL)).reason == "revoked_by_door"


def test_unreachable_directory_gives_no_credit_but_is_not_called_a_forgery(env):
    web, clock, carol, v = env
    ident = check(v, *signed(carol, idm.well_known_url("nowhere.example")))
    assert ident.level == idm.UNSIGNED and not ident.rejected and ident.reason == "directory_unreachable"


@pytest.mark.parametrize("url,why", [
    ("http://carol-agent.example/.well-known/http-message-signatures-directory", "not_https"),
    ("https://127.0.0.1/.well-known/http-message-signatures-directory", "ip_literal_host"),
    ("https://localhost/.well-known/http-message-signatures-directory", "bad_host"),
    ("https://printer.local/.well-known/http-message-signatures-directory", "local_host"),
    ("https://carol-agent.example:8443/.well-known/http-message-signatures-directory", "non_default_port"),
])
def test_door_refuses_to_fetch_keys_from_unsafe_urls(env, url, why):
    web, clock, carol, v = env
    ident = check(v, *signed(carol, url))
    assert ident.rejected and ident.reason.endswith(why) and web.fetches == []


def test_garbage_headers_are_rejected_without_crashing(env):
    *_, v = env
    ident = v.verify("POST", "/mcp", {"signature": "sig1=:!!:", "signature-input": "sig1=(oops"}, b"")
    assert ident.rejected and ident.reason.startswith("malformed")


# -- end to end over HTTP: a signed agent asks the real door for a call ------------------------
def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture
def live_door(tmp_path):
    import uvicorn
    from agent_front_door.server import build_http_app

    web = Web()
    port = _free_port()
    app, door, verifier = build_http_app(ROOT / "config" / "axiom.yaml", tmp_path / "state", fetch=web,
                                         clock=time.time, authority="127.0.0.1:%d" % port)
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    yield web, port, door
    server.should_exit = True
    t.join(timeout=5)


def rpc(port, method, params, key=None, agent_url=None, rid=1, headers_out=None):
    url = "http://127.0.0.1:%d/mcp" % port
    body = json.dumps({"jsonrpc": "2.0", "id": rid, "method": method, "params": params}).encode()
    h = {"content-type": "application/json", "accept": "application/json, text/event-stream",
         "mcp-protocol-version": "2025-11-25"}
    if key:
        h.update(idm.sign_request(key, "POST", url, h, body, agent_url))
    if headers_out is not None:
        headers_out.update(h)
    req = urllib.request.Request(url, data=body, headers=h, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def tool(port, name, args, **kw):
    status, doc = rpc(port, "tools/call", {"name": name, "arguments": args}, **kw)
    if status != 200:
        return status, doc
    res = doc["result"]
    sc = res.get("structuredContent") or json.loads(res["content"][0]["text"])
    return status, sc.get("result", sc)


WHO = {"caller_agent": "carol-assistant", "caller_model": "claude-opus-5-5", "acting_for": "Carol Diaz",
       "contact_email": "carol@carol-agent.example", "topic": "missed_calls"}


def test_end_to_end_signed_call_request_over_http(live_door):
    web, port, door = live_door
    carol = idm.AgentKey.generate()
    web.publish("carol-agent.example", [carol], card={"acts_for": "Carol Diaz (fictional)"})

    # unsigned: may ask for a call; the owner's question says "self reported"
    st, r = tool(port, "request_call", WHO)
    assert st == 200 and r["status"] == "waiting", r
    assert "self reported" in door.owner.read()[-1]["text"]
    st, me = tool(port, "who_am_i", {})
    assert me["label"] == "self reported"

    # signed by a key carol-agent.example publishes: verified, and the call request reaches the owner
    st, me = tool(port, "who_am_i", {}, key=carol, agent_url=CAROL)
    assert st == 200 and me["label"] == "verified: carol-agent.example"
    sent = {}
    st, r = tool(port, "request_call", WHO, key=carol, agent_url=CAROL, headers_out=sent)
    assert st == 200 and r["status"] == "waiting", r
    assert r["receipt"]["verified_domain"] == "carol-agent.example"
    assert "verified: carol-agent.example" in door.owner.read()[-1]["text"]

    # two-sided receipt: door log holds the hash of carol's signature; carol can verify the door's signature
    sig_b64 = sent["Signature"].split("=", 1)[1].strip(":")
    import hashlib
    assert door.receipts.read()[-1]["request_sig_sha256"] == hashlib.sha256(base64.b64decode(sig_b64)).hexdigest()
    with urllib.request.urlopen("http://127.0.0.1:%d%s" % (port, idm.WELL_KNOWN_PATH), timeout=5) as resp:
        assert resp.headers["content-type"] == idm.DIRECTORY_MEDIA_TYPE
        door_dir = json.loads(resp.read())
    assert idm.verify_receipt(r["receipt"], door_dir)

    # forged: mallory signs but claims carol's domain -> 401, the MCP server never sees it
    mallory = idm.AgentKey.generate()
    st, err = tool(port, "request_call", WHO, key=mallory, agent_url=CAROL)
    assert st == 401 and err["reason"] == "key_not_published_by_claimed_owner"


def test_end_to_end_replay_is_refused_over_http(live_door):
    web, port, door = live_door
    carol = idm.AgentKey.generate()
    web.publish("carol-agent.example", [carol])
    url = "http://127.0.0.1:%d/mcp" % port
    body = json.dumps({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
                       "params": {"name": "leave_lead", "arguments": WHO}}).encode()
    h = {"content-type": "application/json", "accept": "application/json, text/event-stream",
         "mcp-protocol-version": "2025-11-25"}
    h.update(idm.sign_request(carol, "POST", url, h, body, CAROL))
    codes = []
    for _ in range(2):
        req = urllib.request.Request(url, data=body, headers=h, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                codes.append((r.status, None))
        except urllib.error.HTTPError as e:
            codes.append((e.code, json.loads(e.read())["reason"]))
    assert codes == [(200, None), (401, "replayed")]
    assert len(door.inbox.read()) == 1           # the replay did nothing


# -- the directory response's own signature (draft: a verifier relying on the domain MUST check it) --
def test_unsigned_directory_response_gives_no_credit(env):
    web, clock, carol, _ = env
    web.publish("carol-agent.example", [carol], sign=False)
    v = idm.Verifier(DOOR, fetch=web, clock=clock)
    ident = check(v, *signed(carol, CAROL))
    assert ident.rejected and ident.reason == "key_not_published_by_claimed_owner"


def test_directory_mirrored_on_another_host_fails(env):
    web, clock, carol, _ = env
    # a copy of carol's file and headers, served from mallory's host: signatures cover @authority
    status, headers, body = web(CAROL)
    web.pages[idm.well_known_url("mallory.example")] = (status, headers, body, None)
    v = idm.Verifier(DOOR, fetch=web, clock=clock)
    ident = check(v, *signed(carol, idm.well_known_url("mallory.example")))
    assert ident.rejected and ident.reason == "key_not_published_by_claimed_owner"


def test_expired_directory_signature_gives_no_credit(env):
    web, clock, carol, _ = env
    old = idm.sign_directory_response([carol], "carol-agent.example", now=NOW - 40 * 86400, ttl=30 * 86400)
    status, headers, body = web(CAROL)
    web.pages[CAROL] = (status, dict(headers, **{k.lower(): v for k, v in old.items()}), body, None)
    v = idm.Verifier(DOOR, fetch=web, clock=clock)
    assert check(v, *signed(carol, CAROL)).reason == "key_not_published_by_claimed_owner"
