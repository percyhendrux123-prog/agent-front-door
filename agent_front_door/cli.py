"""Owner-side CLI for the prototype's fictional owner channel.

  afd owner-inbox            questions waiting on you (the fictional channel)
  afd yes K7Q2XM | afd no K7Q2XM
  afd receipts [--verify]    the door's hash-chained log
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from . import consent_core as cc
from .door import FrontDoor
from .server import ROOT


def main() -> None:
    ap = argparse.ArgumentParser(prog="afd")
    ap.add_argument("cmd", choices=["owner-inbox", "yes", "no", "receipts"])
    ap.add_argument("code", nargs="?")
    ap.add_argument("--verify", action="store_true")
    a = ap.parse_args()
    door = FrontDoor(Path(os.environ.get("AFD_CONFIG") or ROOT / "config" / "axiom.yaml"),
                     Path(os.environ.get("AFD_STATE") or ROOT / ".state"))
    if a.cmd == "owner-inbox":
        for p in door.pending.all():
            if p.get("status") == "pending":
                print(p["code"], p["action"], "from", p["caller"]["caller_agent"], "for", p["caller"]["acting_for"])
    elif a.cmd in ("yes", "no"):
        print(json.dumps(door.owner_answer(a.code or "", a.cmd == "yes")))
    else:
        recs = door.receipts.read()
        if a.verify:
            ok, n, problems = cc.verify_chain(recs)
            print("chain ok" if ok else "chain BROKEN", n, "receipts", *problems, sep="\n")
        else:
            for r in recs:
                print(json.dumps(r, sort_keys=True))


if __name__ == "__main__":
    main()
