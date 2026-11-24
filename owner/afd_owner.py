#!/usr/bin/env python3
"""Owner side of the hosted agent front door. Runs on the owner's own machine and only ever
connects OUT: it pulls new questions from the door, sends each one to the owner's chat, reads the
owner's typed answer ("consent yes CODE" / "consent no CODE") from the local Hermes message store,
and pushes the answer back to the door. Nothing ever connects in to this machine.

No model is involved anywhere in this file. A caller's words are shown to the owner only, marked
"their words, unverified", and the chat message is sent without a copy in any agent's session
(Hermes `send` normally mirrors outgoing text into the chat's agent session; this sender turns that
mirror off for these messages).

Usage:
  afd_owner.py poll [--label TEST]     pull, notify, read answers, push answers (run every minute)
  afd_owner.py answer CODE yes|no      answer by hand instead of from chat
  afd_owner.py receipts --verify       check the door's receipt chain and that both sides agree
  afd_owner.py resend ASK_ID [--label] send a pulled question again from the local copy
  afd_owner.py status                  open questions this machine has sent

Settings (environment):
  AFD_DOOR_URL           https://<door host>            (required)
  AFD_TOKEN_FILE         file holding the owner pull token (chmod 600)  (required)
  AFD_STATE_DIR          local state; default ~/.hermes/plugin-data/agent-front-door
  AFD_NOTIFY_TARGET      hermes send target for the owner; default "telegram" (home channel)
  AFD_OWNER_CHAT_USER    the owner's chat user id; only that user's messages can answer (required for chat answers)
  AFD_OWNER_PLATFORM     chat platform whose messages are read for answers; default "telegram"
  AFD_HERMES_DB          Hermes message store; default ~/.hermes/state.db (opened read-only)
  AFD_HERMES_AGENT       Hermes source dir; default ~/.hermes/hermes-agent
  AFD_HERMES_PYTHON      Python that runs Hermes; default: read from the `hermes` launcher
  AFD_SENDER             "hermes-nomirror" (default) or "stdout" (dry run; prints instead of sending)
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

HOME = Path.home()
DOOR = os.environ.get("AFD_DOOR_URL", "").rstrip("/")
STATE = Path(os.environ.get("AFD_STATE_DIR", str(HOME / ".hermes/plugin-data/agent-front-door")))
TARGET = os.environ.get("AFD_NOTIFY_TARGET", "telegram")
OWNER_USER = os.environ.get("AFD_OWNER_CHAT_USER", "").strip()
OWNER_PLATFORM = os.environ.get("AFD_OWNER_PLATFORM", "telegram").strip()
HDB = Path(os.environ.get("AFD_HERMES_DB", str(HOME / ".hermes/state.db")))
HAGENT = Path(os.environ.get("AFD_HERMES_AGENT", str(HOME / ".hermes/hermes-agent")))
SENDER = os.environ.get("AFD_SENDER", "hermes-nomirror")
UA = "agent-front-door-owner/0.2 (+https://github.com/percyhendrux123-prog/agent-front-door)"
ANSWER = re.compile(r"^\s*consent\s+(yes|no)\s+([A-Za-z0-9]{6})\s*[.!]?\s*$", re.I | re.M)
VERB = {"request_call": "request a call", "ask_question": "ask a question", "leave_lead": "leave a lead"}
GENESIS = "0" * 64


# -- small helpers ---------------------------------------------------------------------------------
def die(msg: str, code: int = 2) -> None:
    print("afd_owner: " + msg, file=sys.stderr)
    sys.exit(code)


def token() -> str:
    p = os.environ.get("AFD_TOKEN_FILE", "")
    if not p or not Path(p).is_file():
        die("AFD_TOKEN_FILE is not set or missing")
    if Path(p).stat().st_mode & 0o077:
        die("token file must be private (chmod 600)")
    return Path(p).read_text().strip()


def call(method: str, path: str, body: dict | None = None) -> tuple[int, dict]:
    if not (DOOR.startswith("https://") or DOOR.startswith("http://127.0.0.1:")):
        die("AFD_DOOR_URL must be an https URL")
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(DOOR + path, data=data, method=method, headers={
        "authorization": "Bearer " + token(), "content-type": "application/json", "user-agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except Exception:
            return e.code, {}


def load(name: str, default):
    p = STATE / name
    return json.loads(p.read_text()) if p.exists() else default


def save(name: str, obj) -> None:
    STATE.mkdir(parents=True, exist_ok=True)
    tmp = STATE / (name + ".tmp")
    tmp.write_text(json.dumps(obj, indent=1, ensure_ascii=False))
    os.chmod(tmp, 0o600)
    tmp.replace(STATE / name)


def canon(o: dict) -> str:
    return json.dumps({k: o[k] for k in sorted(o)}, separators=(",", ":"), ensure_ascii=False)


def sha(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def receipt(**fields) -> dict:
    """Owner-side receipt chain (same hash rule as the door)."""
    STATE.mkdir(parents=True, exist_ok=True)
    p = STATE / "receipts.jsonl"
    last = None
    if p.exists():
        lines = [l for l in p.read_text().splitlines() if l.strip()]
        last = json.loads(lines[-1]) if lines else None
    rec = {"seq": (last["seq"] + 1) if last else 1, "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "side": "owner", **fields, "prev": last["hash"] if last else GENESIS}
    rec["hash"] = sha(rec["prev"] + "\n" + canon(rec))
    with open(p, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    os.chmod(p, 0o600)
    return rec


def hermes_python() -> str:
    env = os.environ.get("AFD_HERMES_PYTHON")
    if env:
        return env
    launcher = shutil.which("hermes")
    if launcher:
        m = re.search(r"exec\s+(\S+/python3?)\s", Path(launcher).read_text(errors="ignore"))
        if m:
            return m.group(1)
    return sys.executable


SEND_SNIPPET = r"""
import json, sys
sys.path.insert(0, sys.argv[1])
sys._hermes_pin_default_home = True
import hermes_bootstrap  # puts Hermes's own dependencies on the path, as the `hermes` launcher does
from hermes_cli.send_cmd import _load_hermes_env
_load_hermes_env()
import gateway.outbound.send as s
s._mirror_sent_message = lambda *a, **k: False   # owner-only text: no copy into any agent session
d = json.load(sys.stdin)
r = json.loads(s.send_message_tool({"action": "send", "target": d["target"], "message": d["message"]}))
print(json.dumps({"success": bool(r.get("success")), "mirrored": bool(r.get("mirrored")), "error": r.get("error")}))
"""


def send(message: str) -> bool:
    if SENDER == "stdout":
        print("---- would send to %s ----\n%s\n----" % (TARGET, message))
        return True
    env = dict(os.environ)
    env.setdefault("HERMES_HOME", str(HOME / ".hermes"))
    p = subprocess.run([hermes_python(), "-I", "-c", SEND_SNIPPET, str(HAGENT)], input=json.dumps(
        {"target": TARGET, "message": message}), capture_output=True, text=True, timeout=90, env=env)
    try:
        r = json.loads(p.stdout.strip().splitlines()[-1])
    except Exception:
        print("send failed (exit %s)" % p.returncode, file=sys.stderr)
        return False
    if r.get("mirrored"):
        print("warning: message was mirrored into an agent session", file=sys.stderr)
    return bool(r.get("success")) and not r.get("mirrored")


def render(item: dict, lbl: str) -> str:
    c, f = item["caller"], item["fields"]
    # "verified: <domain>" only when the door checked a Web Bot Auth signature; otherwise "self reported".
    who = "%s (model %s, %s)" % (c["caller_agent"], c["caller_model"], c.get("identity_label") or "self reported")
    words = f.get("note") or "(none)"
    pre = (lbl.strip() + ": ") if lbl else ""
    if item["kind"] == "lead":
        return (pre + "Front door lead: %s left a lead for %s.\nTopic: %s. Contact: %s.\n"
                "Their words, unverified: \"%s\"\nNo reply needed." % (who, f["name"], f["topic"], f["contact"], words))
    return (pre + "Front door: %s asks to %s for %s.\nTopic: %s. Window: %s. Contact: %s.\n"
            "Their words, unverified: \"%s\"\nReply: consent yes %s  /  consent no %s\n"
            "Type the reply as a new message (not a swipe reply) so their words never reach an agent."
            % (who, VERB.get(item["action"], item["action"]), f["name"], f["topic"], f["window"], f["contact"],
               words, item["code"], item["code"]))


# -- the three moves -------------------------------------------------------------------------------
def notify(lbl: str) -> None:
    st, res = call("POST", "/owner/pull", {})
    if st != 200:
        print("pull failed: HTTP %s %s" % (st, res.get("error", "")), file=sys.stderr)
        return
    sent = load("sent.json", {})
    acked = []
    for item in res.get("items", []):
        aid = item["ask_id"]
        if aid in sent and sent[aid].get("notified"):
            acked.append(aid)  # sent before, ack was lost: ack again, do not resend
            continue
        if not send(render(item, lbl)):
            continue
        sent[aid] = {"code": item.get("code"), "kind": item["kind"], "action": item["action"], "notified": time.time(),
                     "caller_agent": item["caller"]["caller_agent"], "status": "open" if item.get("code") else "fyi"}
        save("sent.json", sent)
        with open(STATE / "inbox.jsonl", "a", encoding="utf-8") as fh:  # owner's own copy; not for agents
            fh.write(json.dumps(item, ensure_ascii=False) + "\n")
        os.chmod(STATE / "inbox.jsonl", 0o600)
        acked.append(aid)
    if acked:
        st, r = call("POST", "/owner/ack", {"ask_ids": acked, "via": TARGET})
        for dr in r.get("acked", []):
            receipt(event="owner_notified", ask_id=dr["ask_id"], via=TARGET, door_seq=dr["seq"], door_hash=dr["hash"])
            print("notified %s (door receipt #%s)" % (dr["ask_id"], dr["seq"]))


def chat_answers() -> list[tuple[str, bool, float]]:
    if not OWNER_USER or not HDB.exists():
        return []
    cur = load("cursor.json", {})
    since = float(cur.get("since") or time.time() - 120)
    con = sqlite3.connect("file:%s?mode=ro" % HDB, uri=True, timeout=5)
    try:
        rows = con.execute(
            "SELECT m.content, m.timestamp FROM messages m JOIN sessions s ON s.id = m.session_id "
            "WHERE s.source = ? AND s.user_id = ? AND m.role = 'user' AND m.timestamp > ? ORDER BY m.timestamp",
            (OWNER_PLATFORM, OWNER_USER, since)).fetchall()
    finally:
        con.close()
    out = []
    for content, ts in rows:
        for m in ANSWER.finditer(content or ""):
            out.append((m.group(2).upper(), m.group(1).lower() == "yes", float(ts)))
        since = max(since, float(ts))
    save("cursor.json", {"since": since})
    return out


def push_answer(code: str, yes: bool, via: str) -> bool:
    sent = load("sent.json", {})
    mine = [a for a, v in sent.items() if v.get("code") == code and v.get("status") == "open"]
    if not mine:
        return False  # not a question this machine sent (could be another tool's code): leave it alone
    st, r = call("POST", "/owner/answer", {"code": code, "answer": "yes" if yes else "no", "via": via})
    aid = mine[0]
    if st == 200 and r.get("ok"):
        sent[aid]["status"] = "yes" if yes else "no"
        save("sent.json", sent)
        dr = r["receipt"]
        receipt(event="owner_answer", ask_id=aid, answer=r["answer"], via=via, door_seq=dr["seq"], door_hash=dr["hash"])
        print("answer %s -> %s (door receipt #%s)" % (code, r["answer"], dr["seq"]))
        if via != "manual":
            send("Front door: %s recorded for %s (receipt #%s)." % (r["answer"], code, dr["seq"]))
        return True
    if st == 409:
        sent[aid]["status"] = "closed"
        save("sent.json", sent)
    print("answer %s not taken: HTTP %s %s" % (code, st, r.get("error", "")), file=sys.stderr)
    return False


def cmd_poll(a) -> None:
    STATE.mkdir(parents=True, exist_ok=True)
    lock = open(STATE / ".lock", "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return  # another poll is running
    notify(a.label or "")
    for code, yes, _ts in chat_answers():
        push_answer(code, yes, OWNER_PLATFORM)


def cmd_answer(a) -> None:
    if not push_answer(a.code.upper(), a.answer == "yes", "manual"):
        sys.exit(1)


def door_receipts() -> list[dict]:
    out, since = [], 0
    while True:
        st, r = call("GET", "/owner/receipts?since=%d&limit=500" % since)
        if st != 200:
            die("receipts fetch failed: HTTP %s" % st)
        batch = r.get("receipts", [])
        out += batch
        if len(batch) < 500:
            return out
        since = batch[-1]["seq"]


def verify_chain(recs: list[dict]) -> tuple[bool, str]:
    prev = GENESIS
    for i, r in enumerate(recs, 1):
        body = {k: v for k, v in r.items() if k != "hash"}
        if r.get("seq") != i or r.get("prev") != prev or sha(prev + "\n" + canon(body)) != r.get("hash"):
            return False, "breaks at seq %s" % r.get("seq")
        prev = r["hash"]
    return True, "%d receipts, head %s" % (len(recs), prev[:16])


def cmd_receipts(a) -> None:
    door = door_receipts()
    ok_d, msg_d = verify_chain(door)
    print("door chain:  %s  %s" % ("OK" if ok_d else "BROKEN", msg_d))
    p = STATE / "receipts.jsonl"
    mine = [json.loads(l) for l in p.read_text().splitlines() if l.strip()] if p.exists() else []
    ok_o, msg_o = verify_chain(mine)
    print("owner chain: %s  %s" % ("OK" if ok_o else "BROKEN", msg_o))
    hashes = {r["hash"]: r for r in door}
    missing = [r for r in mine if r.get("door_hash") and r["door_hash"] not in hashes]
    print("both sides agree: %s (%d owner receipts point at door receipts; %d missing)" %
          ("YES" if not missing else "NO", sum(1 for r in mine if r.get("door_hash")), len(missing)))
    sys.exit(0 if ok_d and ok_o and not missing else 1)


def cmd_resend(a) -> None:
    """Send an already-pulled question again from this machine's own copy (e.g. after a failed or dry-run send)."""
    p = STATE / "inbox.jsonl"
    items = [json.loads(l) for l in p.read_text().splitlines() if l.strip()] if p.exists() else []
    item = next((i for i in reversed(items) if i["ask_id"] == a.ask_id.upper()), None)
    if not item:
        die("no local copy of %s" % a.ask_id)
    if not send(render(item, a.label or "")):
        die("send failed", 1)
    receipt(event="owner_notified_resend", ask_id=item["ask_id"], via=TARGET)
    print("resent %s" % item["ask_id"])


def cmd_status(a) -> None:
    for aid, v in load("sent.json", {}).items():
        print("%s  %-12s %-6s %s  %s" % (aid, v.get("action"), v.get("code") or "-", v.get("status"), v.get("caller_agent")))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("poll"); p.add_argument("--label", default=""); p.set_defaults(fn=cmd_poll)
    p = sub.add_parser("answer"); p.add_argument("code"); p.add_argument("answer", choices=["yes", "no"]); p.set_defaults(fn=cmd_answer)
    p = sub.add_parser("receipts"); p.add_argument("--verify", action="store_true"); p.set_defaults(fn=cmd_receipts)
    p = sub.add_parser("resend"); p.add_argument("ask_id"); p.add_argument("--label", default=""); p.set_defaults(fn=cmd_resend)
    p = sub.add_parser("status"); p.set_defaults(fn=cmd_status)
    a = ap.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
