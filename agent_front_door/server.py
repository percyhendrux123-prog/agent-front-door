"""MCP wiring for the front door. Run: ``uv run afd-server`` (stdio) or ``uv run afd-server --http``.

Every tool is a thin call into FrontDoor. The tool descriptions are written for an outside model:
they say what the door will and won't do, so a well-behaved agent never has to guess.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import Any, Dict, Literal

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

from .door import FrontDoor, Refused

ROOT = Path(__file__).resolve().parent.parent
Topic = Literal["client_care", "missed_calls", "follow_up", "records", "front_door_for_my_business", "other"]
Window = Literal["weekday_morning", "weekday_afternoon", "any"]

RULES = """This is a business's front door for AI agents. It is open to any model.
Read: list_facts and lookup_fact return the business's own facts page, word for word. Nothing is generated.
Act: request_call, ask_question and leave_lead. Say who you are (caller_agent), what model you run on
(caller_model) and who you act for (acting_for). Each ask is decided by the owner's rules:
on the allowed list it goes through; otherwise the owner gets one yes/no question and you call
check_request later; a no is remembered. Always refused, whatever you are allowed: prices, payments,
refunds, deleting data, sending messages to anyone else, and commitments in the owner's name.
Notes are capped at 280 characters, links are removed, and they are read by the owner, not by a model.
Every answer carries a receipt (seq, hash, prev) from the door's hash-chained log; keep it."""


def build(config: Path | None = None, state_dir: Path | None = None) -> tuple[MCPServer, FrontDoor]:
    config = Path(config or os.environ.get("AFD_CONFIG") or ROOT / "config" / "axiom.yaml")
    state_dir = Path(state_dir or os.environ.get("AFD_STATE") or ROOT / ".state")
    door = FrontDoor(config, state_dir)
    b = door.business
    mcp = MCPServer(name="agent-front-door", title="%s front door for AI agents" % b["name"],
                    instructions=RULES, version="0.1.0", website_url=b["facts_url"])
    read = ToolAnnotations(read_only_hint=True, idempotent_hint=True, open_world_hint=False)
    act = ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=True, open_world_hint=False)

    def guard(fn):
        try:
            return fn()
        except Refused as e:
            return {"status": "refused", "message": str(e)}

    @mcp.tool(annotations=read, description="The door's rules in plain English: what it does, what it always refuses.")
    def door_rules() -> Dict[str, Any]:
        return {"business": b["name"], "rules": RULES, "facts_source": b["facts_url"]}

    @mcp.tool(annotations=read, description="All facts from the business's public facts page, word for word, with the page hash.")
    def list_facts(caller_agent: str = "anon") -> Dict[str, Any]:
        if not door.read_allowed(caller_agent):
            return {"status": "refused", "message": "read limit reached; try in a minute"}
        return door.list_facts()

    @mcp.tool(annotations=read, description="Find the one fact on the page that answers a question. Returns found=false rather than guess.")
    def lookup_fact(question: str, caller_agent: str = "anon") -> Dict[str, Any]:
        if not door.read_allowed(caller_agent):
            return {"status": "refused", "message": "read limit reached; try in a minute"}
        return door.lookup(question)

    @mcp.tool(annotations=act, description="Ask for a call with the business on behalf of a person. Goes through the owner's consent rules.")
    def request_call(caller_agent: str, caller_model: str, acting_for: str, contact_email: str,
                     topic: Topic = "other", preferred_window: Window = "any", note: str = "",
                     caller_key: str = "") -> Dict[str, Any]:
        return guard(lambda: door.act("request_call", door.caller(caller_agent, caller_model, acting_for, caller_key),
                                      {"contact_email": contact_email, "topic": topic,
                                       "preferred_window": preferred_window, "note": note}))

    @mcp.tool(annotations=act, description="Ask the business a question. Answered from the facts page when it can be; otherwise put to the owner under the consent rules.")
    def ask_question(caller_agent: str, caller_model: str, acting_for: str, question: str, contact_email: str,
                     caller_key: str = "") -> Dict[str, Any]:
        def run():
            c = door.caller(caller_agent, caller_model, acting_for, caller_key)
            hit = door.lookup(question)
            if hit.get("found") and hit["match_score"] >= 0.75:
                return dict(hit, status="answered_from_page")
            return door.act("ask_question", c, {"contact_email": contact_email, "note": question, "question": question})
        return guard(run)

    @mcp.tool(annotations=act, description="Leave a short lead for the business: who, how to reach them, what they need.")
    def leave_lead(caller_agent: str, caller_model: str, acting_for: str, contact_email: str,
                   topic: Topic = "other", note: str = "", caller_key: str = "") -> Dict[str, Any]:
        return guard(lambda: door.act("leave_lead", door.caller(caller_agent, caller_model, acting_for, caller_key),
                                      {"contact_email": contact_email, "topic": topic, "note": note}))

    @mcp.tool(annotations=ToolAnnotations(read_only_hint=False, idempotent_hint=True, open_world_hint=False),
              description="Check a request that was waiting on the owner. If the owner said yes, this completes it.")
    def check_request(request_id: str, caller_agent: str, caller_model: str, acting_for: str,
                      caller_key: str = "") -> Dict[str, Any]:
        return guard(lambda: door.check(request_id, door.caller(caller_agent, caller_model, acting_for, caller_key)))

    return mcp, door


def main() -> None:
    ap = argparse.ArgumentParser(description="Agent front door MCP server")
    ap.add_argument("--http", action="store_true", help="serve streamable HTTP on 127.0.0.1 instead of stdio")
    ap.add_argument("--port", type=int, default=8765)
    args = ap.parse_args()
    mcp, _ = build()
    if args.http:
        mcp.run("streamable-http", host="127.0.0.1", port=args.port)
    else:
        mcp.run()


if __name__ == "__main__":
    main()
