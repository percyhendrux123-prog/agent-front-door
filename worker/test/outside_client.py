"""Outside-client check of the hosted door's read path, using the official MCP Python SDK.

Usage: uv run python worker/test/outside_client.py https://<host>/mcp

Checks, and prints what it saw:
 1. the client connects over streamable HTTP and lists the 3 read tools (marked read-only) and the
    4 act tools (none destructive); act-path checks live in act_e2e.py;
 2. list_facts returns the same words as the LIVE deployaxiom.com/facts page, fetched now and
    parsed with the door's own parser (byte check: page sha256 + every question/answer equal);
 3. lookup_fact reads 3 facts;
 4. a question about prices or money is refused;
 5. every lookup in parity.json gives the same fact (or refusal) as the Python door.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import sys
import urllib.request
from pathlib import Path

from mcp import Client

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from agent_front_door.facts import Facts  # noqa: E402

LIVE = "https://deployaxiom.com/facts/"
ACT_TOOLS = {"request_call", "ask_question", "leave_lead", "check_request"}


def sc(r):
    s = r.structured_content or {}
    return s.get("result", s) if isinstance(s, dict) else s


async def main(url: str) -> int:
    raw = urllib.request.urlopen(urllib.request.Request(
        LIVE, headers={"User-Agent": "agent-front-door-check/0.1"}), timeout=20).read()
    live = Facts(raw.decode("utf-8"), LIVE)
    live_sha = hashlib.sha256(raw).hexdigest()
    fails = []

    def check(name, cond, detail=""):
        print(("PASS " if cond else "FAIL ") + name + (("  " + detail) if detail else ""))
        if not cond:
            fails.append(name)

    async with Client(url) as c:
        tools = sorted(t.name for t in (await c.list_tools()).tools)
        print("tools/list ->", tools)
        check("3 read tools + 4 act tools", tools == sorted(["door_rules", "list_facts", "lookup_fact"] + list(ACT_TOOLS)))
        listed = {t.name: t for t in (await c.list_tools()).tools}
        check("read tools marked read-only", all(listed[n].annotations.read_only_hint for n in ("door_rules", "list_facts", "lookup_fact")))
        check("no tool marked destructive", not any(t.annotations.destructive_hint for t in listed.values()))

        rules = sc(await c.call_tool("door_rules", {}))
        print("door_rules.read_only ->", rules.get("read_only"))

        facts = sc(await c.call_tool("list_facts", {"caller_agent": "outside-check"}))
        check("page sha256 matches live page now", facts["page_sha256"] == live_sha,
              "door=%s live=%s" % (facts["page_sha256"][:16], live_sha[:16]))
        same = [(a["id"], a["question"], a["answer"]) for a in facts["facts"]] == \
               [(b["id"], b["question"], b["answer"]) for b in live.items]
        check("every fact is the live page's words", same, "%d facts" % len(facts["facts"]))

        for q in ["Where are you located?", "how do I book a call", "Does Deploy Axiom handle HIPAA compliance?"]:
            r = sc(await c.call_tool("lookup_fact", {"question": q}))
            print("lookup_fact(%r) -> %s %s: %s" % (q, r.get("fact_id"), r.get("question"), (r.get("answer") or "")[:110]))
            check("read fact for %r" % q, r.get("found") is True and live.is_verbatim(r["answer"]))

        for q in ["How much does it cost?", "Can I pay you by credit card?", "I want a refund"]:
            r = sc(await c.call_tool("lookup_fact", {"question": q}))
            print("lookup_fact(%r) -> status=%s refused=%s message=%s" % (q, r.get("status"), r.get("refused"), r.get("message", "")[:80]))
            check("money ask refused: %r" % q, r.get("status") == "refused" and "$" not in json.dumps(r))

        bad = await c.call_tool("request_call", {"caller_agent": "outside-check", "caller_model": "none",
                                                 "acting_for": "Nobody", "contact_email": "not-an-email", "topic": "other"})
        r = sc(bad)
        check("act tool with bad input refused before anything is recorded", bad.is_error and r.get("status") == "refused",
              str(r)[:100])

        parity = json.loads((ROOT / "worker" / "test" / "parity.json").read_text())
        mism = []
        print("(waiting 65s so the per-IP rate limit of 30/min resets before the parity run)")
        await asyncio.sleep(65)
        for p in parity:
            if not p["q"]:
                continue
            r = sc(await c.call_tool("lookup_fact", {"question": p["q"]}))
            got = ("refused", r.get("refused")) if r.get("status") == "refused" else (r.get("fact_id"), r.get("match_score"))
            want = ("refused", None) if p["floor"] else (p["id"], p["score"])
            if p["floor"]:
                ok = got[0] == "refused"
            else:
                ok = got == want
            if not ok:
                mism.append((p["q"], got, want))
        check("lookup parity with the Python door (%d questions)" % (len(parity) - 1), not mism, str(mism)[:300])

    print("RESULT:", "ALL PASS" if not fails else "FAILED: %s" % fails)
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main(sys.argv[1])))
