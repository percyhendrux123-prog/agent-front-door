"""End-to-end check of the door's act path with fictional callers.

Usage:
  python worker/test/act_e2e.py URL --token-file FILE [--owner-sim] [--cap]

  URL           door origin, e.g. http://127.0.0.1:8787 or https://<door>.workers.dev
  --token-file  the owner pull token (to read the owner queue and receipts)
  --owner-sim   answer the owner questions from this script (local runs only). Without it the
                script stops after the asks and prints the codes for the real owner path.
  --cap         also walk the daily owner cap (sends extra asks; local runs only)

Everything here is fictional: example.com addresses, made-up people and agents.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.error
import urllib.request

GENESIS = "0" * 64
fails: list[str] = []


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + (("  " + str(detail)) if detail else ""))
    if not cond:
        fails.append(name)


class Door:
    def __init__(self, origin, token, ip="198.51.100.7"):
        self.origin, self.token, self.ip, self.n = origin.rstrip("/"), token, ip, 0

    def http(self, method, path, body=None, owner=False, ip=None):
        h = {"content-type": "application/json", "accept": "application/json, text/event-stream",
             "user-agent": "afd-e2e/0.2"}
        if owner:
            h["authorization"] = "Bearer " + self.token
        if self.origin.startswith("http://127.0.0.1") or self.origin.startswith("http://localhost"):
            h["cf-connecting-ip"] = ip or self.ip
        req = urllib.request.Request(self.origin + path, method=method, headers=h,
                                     data=json.dumps(body).encode() if body is not None else None)
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.status, json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    def rpc(self, method, params=None, ip=None):
        self.n += 1
        st, r = self.http("POST", "/mcp", {"jsonrpc": "2.0", "id": self.n, "method": method, "params": params or {}}, ip=ip)
        return r

    def tool(self, name, args, ip=None):
        r = self.rpc("tools/call", {"name": name, "arguments": args}, ip=ip)
        res = r.get("result", {})
        return res.get("structuredContent") or json.loads(res["content"][0]["text"])


def caller(agent, model, person, email):
    return {"caller_agent": agent, "caller_model": model, "acting_for": person, "contact_email": email}


def canon(o):
    return json.dumps({k: o[k] for k in sorted(o)}, separators=(",", ":"), ensure_ascii=False)


def verify(recs):
    prev = GENESIS
    for i, r in enumerate(recs, 1):
        body = {k: v for k, v in r.items() if k != "hash"}
        if r["seq"] != i or r["prev"] != prev or hashlib.sha256((prev + "\n" + canon(body)).encode()).hexdigest() != r["hash"]:
            return False
        prev = r["hash"]
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url")
    ap.add_argument("--token-file", required=True)
    ap.add_argument("--owner-sim", action="store_true")
    ap.add_argument("--cap", action="store_true")
    a = ap.parse_args()
    d = Door(a.url, open(a.token_file).read().strip())
    my_receipts = []

    init = d.rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "e2e", "version": "0"}})
    check("initialize", init.get("result", {}).get("serverInfo", {}).get("name") == "agent-front-door")
    tools = sorted(t["name"] for t in d.rpc("tools/list")["result"]["tools"])
    check("7 tools listed", tools == sorted(["door_rules", "list_facts", "lookup_fact", "request_call", "ask_question",
                                             "leave_lead", "check_request"]), tools)
    st, r = d.http("POST", "/owner/pull", {})
    check("owner side closed without token", d.http("POST", "/owner/pull", {}, owner=False)[0] == 401)

    # 1. request_call by a fictional caller -> waiting
    dana = caller("Atlas Assist", "fictional-model-1", "Dana Reyes", "dana@example.com")
    rc = d.tool("request_call", {**dana, "topic": "missed_calls", "preferred_window": "weekday_morning",
                                  "note": "Dana runs a 3-person agency and misses calls after 5. See https://evil.example/x"})
    check("request_call -> waiting", rc.get("status") == "waiting", rc.get("reason"))
    my_receipts.append(rc["receipt"])
    rid_dana = rc["request_id"]
    again = d.tool("check_request", {"request_id": rid_dana, "caller_agent": "Atlas Assist"})
    check("check before answer -> still waiting", again.get("reason") == "still_waiting")
    my_receipts.append(again["receipt"])
    other = d.tool("check_request", {"request_id": rid_dana, "caller_agent": "Someone Else"})
    check("another caller cannot read it", other.get("status") == "refused")

    # 2. floor words refused, even on an otherwise fine request
    fl = d.tool("request_call", {**caller("Atlas Assist", "fictional-model-1", "Sam Ortiz", "sam@example.com"),
                                 "topic": "other", "note": "What is your price for this?"})
    check("price ask refused (never-list)", fl.get("reason") == "always_denied", fl.get("message", "")[:60])
    my_receipts.append(fl["receipt"])

    # 3. ask_question answered from the page (no owner question)
    aq = d.tool("ask_question", {**caller("Gemma Desk", "fictional-model-2", "Lee Park", "lee@example.com"),
                                 "question": "Where is Deploy Axiom located?"})
    check("page question answered from page", aq.get("status") == "answered_from_page", aq.get("fact_id"))

    # 4. leave_lead allowed
    ld = d.tool("leave_lead", {**caller("Gemma Desk", "fictional-model-2", "Lee Park", "lee@example.com"),
                               "topic": "follow_up", "note": "Lee wants follow-up help for a small CPA office."})
    check("leave_lead allowed", ld.get("status") == "allowed", ld.get("message"))
    my_receipts.append(ld["receipt"])

    # 5. a second fictional caller asks a question the page cannot answer
    q2 = d.tool("ask_question", {**caller("Orbit Helper", "fictional-model-3", "Kim Vale", "kim@example.com"),
                                 "question": "Can the agent speak Spanish with my callers?"})
    check("off-page question -> waiting", q2.get("status") == "waiting", q2.get("reason"))
    rid_kim = q2["request_id"]

    st, pull = d.http("POST", "/owner/pull", {}, owner=True)
    items = {i["ask_id"]: i for i in pull.get("items", [])}
    check("owner queue has the 2 questions + 1 lead", {rid_dana, rid_kim, ld["request_id"]} <= set(items), sorted(items))
    note = items.get(rid_dana, {}).get("fields", {}).get("note", "")
    check("caller note: links stripped", "evil.example" not in note and "[link removed]" in note, note)
    check("caller note <= 280 chars", len(note) <= 280)

    if not a.owner_sim:
        print("\nOwner codes (answer through the real owner path):")
        for i in items.values():
            print("  %s  %s  %s" % (i["ask_id"], i["action"], i.get("code")))
        print("request ids:", json.dumps({"dana": rid_dana, "kim": rid_kim}))
        return finish(d, my_receipts)

    st, ack = d.http("POST", "/owner/ack", {"ask_ids": list(items), "via": "e2e"}, owner=True)
    check("owner ack writes receipts", len(items) > 0 and len(ack.get("acked", [])) == len(items))
    st, y = d.http("POST", "/owner/answer", {"code": items[rid_dana]["code"], "answer": "yes", "via": "e2e"}, owner=True)
    check("owner yes recorded", st == 200 and y.get("answer") == "yes")
    st, n = d.http("POST", "/owner/answer", {"code": items[rid_kim]["code"], "answer": "no", "via": "e2e"}, owner=True)
    check("owner no recorded", st == 200 and n.get("answer") == "no")
    st, _ = d.http("POST", "/owner/answer", {"code": items[rid_kim]["code"], "answer": "yes", "via": "e2e"}, owner=True)
    check("second answer to same code rejected", st == 409)

    done = d.tool("check_request", {"request_id": rid_dana, "caller_agent": "Atlas Assist"})
    want = ("Recorded for Deploy Axiom. If the work fits, P. K. Stewart takes the call. To pick a time now: "
            "https://calendar.app.google/rD42RF3YVLaRV52J6")
    check("yes -> exact approved message", done.get("message") == want, done.get("message"))
    my_receipts.append(done["receipt"])
    once = d.tool("check_request", {"request_id": rid_dana, "caller_agent": "Atlas Assist"})
    check("yes carried out once", once.get("reason") == "already_done")
    my_receipts.append(once["receipt"])
    no = d.tool("check_request", {"request_id": rid_kim, "caller_agent": "Orbit Helper"})
    check("no -> refused", no.get("reason") == "owner_declined")
    re_ask = d.tool("ask_question", {**caller("Orbit Helper", "fictional-model-3", "Kim Vale", "kim@example.com"),
                                     "question": "Can the agent speak Spanish with my callers please?"})
    check("no remembered (similar re-ask not sent to owner)", re_ask.get("reason") == "remembered_no", re_ask.get("reason"))

    if a.cap:
        # Fill the owner's daily limit with distinct fictional callers from distinct addresses.
        st, p0 = d.http("POST", "/owner/pull", {}, owner=True)
        reasons = []
        for i in range(12):
            r = d.tool("request_call", {**caller("Cap Bot %d" % i, "fictional", "Person %d" % i, "p%d@example.com" % i),
                                        "topic": "other"}, ip="203.0.113.%d" % (i + 10))
            reasons.append(r.get("reason"))
        check("daily owner cap holds at 10", "daily_owner_cap" in reasons, reasons)

    return finish(d, my_receipts)


def finish(d, my_receipts):
    st, r = d.http("GET", "/owner/receipts?since=0&limit=500", owner=True)
    recs = r.get("receipts", [])
    check("door receipt chain verifies", verify(recs), "%d receipts" % len(recs))
    door = {x["hash"]: x for x in recs}
    agree = all(m["hash"] in door and door[m["hash"]]["prev"] == m["prev"] for m in my_receipts)
    check("caller's receipts match the door's chain", agree, "%d caller receipts" % len(my_receipts))
    st, head = d.http("GET", "/receipts/head")
    check("public receipts head", st == 200 and head.get("hash") == (recs[-1]["hash"] if recs else GENESIS), head.get("seq"))
    print("\nRESULT:", "ALL PASS" if not fails else "FAILED: " + ", ".join(fails))
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
