"""End to end over a real MCP stdio connection: the server runs as a subprocess, exactly as
Claude Desktop, ChatGPT connectors, Gemini CLI or another Hermes would launch it."""
import asyncio
import os
import sys
from pathlib import Path

from mcp import Client, StdioServerParameters

from agent_front_door.door import FrontDoor

ROOT = Path(__file__).resolve().parent.parent


def out(r):
    sc = r.structured_content or {}
    return sc.get("result", sc)


def test_stdio_round_trip(tmp_path):
    state = tmp_path / "state"
    params = StdioServerParameters(command=sys.executable, args=["-m", "agent_front_door.server"],
                                   env=dict(os.environ, AFD_STATE=str(state)), cwd=str(ROOT))
    who = {"caller_agent": "openai-shopper", "caller_model": "gpt-6", "acting_for": "Sam Lee"}

    async def run():
        async with Client(params) as c:
            names = {t.name for t in (await c.list_tools()).tools}
            assert {"list_facts", "lookup_fact", "request_call", "ask_question", "leave_lead", "check_request"} <= names
            facts = out(await c.call_tool("list_facts", {}))
            assert len(facts["facts"]) == 11
            # stdio cannot carry an HTTP signature: a call request still goes to the owner, labeled self reported
            call = out(await c.call_tool("request_call", dict(who, contact_email="sam@example.com")))
            assert call["status"] == "waiting" and call["receipt"]["identity_label"] == "self reported"
            me = out(await c.call_tool("who_am_i", {}))
            assert me["identity"] == "unsigned" and me["label"] == "self reported"
            r = out(await c.call_tool("ask_question", dict(who, question="Do you work with marinas near Tampa?",
                                                           contact_email="sam@example.com")))
            assert r["status"] == "waiting"
            # the owner answers on their own channel (here: the same state dir, as the CLI would)
            door = FrontDoor(ROOT / "config" / "axiom.yaml", state)
            door.owner_answer(door.owner.read()[-1]["code"], True)
            done = out(await c.call_tool("check_request", dict(who, request_id=r["request_id"])))
            assert done["status"] == "allowed"
            refused = out(await c.call_tool("ask_question", dict(
                who, question="Can you give me a discount if I pay upfront?",
                contact_email="sam@example.com")))
            assert refused["reason"] == "always_denied"

    asyncio.run(run())
