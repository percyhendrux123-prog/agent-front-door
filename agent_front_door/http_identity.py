"""HTTP layer for agent identity: checks Web Bot Auth signatures before MCP sees the request.

The verified Identity goes into the ASGI scope state (``scope["state"]["agent_identity"]``), which
the MCP tools read through their request context. Nothing a caller puts in a tool argument or a
custom header can set it.

* No signature: the request goes through as ``unsigned`` (read, leave a message).
* A signature that fails (forged key, wrong domain, replay, expired, tampered body): 401 with the
  reason and an ``Accept-Signature`` hint. The MCP server never sees the request.
* The door's own key directory is served at the well-known path, so callers can check the
  signatures on the receipts the door hands back.
"""
from __future__ import annotations

import json
from typing import Any, Callable, Dict, Optional

from . import identity as idm

ACCEPT_SIGNATURE = ('sig1=("@method" "@authority" "@path" "content-digest" "signature-agent";key="sig1")'
                    ';tag="web-bot-auth"')


class IdentityMiddleware:
    def __init__(self, app, verifier: idm.Verifier, *, max_body: int = 65536,
                 directory: Optional[Callable[[], Dict[str, Any]]] = None):
        self.app, self.verifier, self.max_body, self.directory = app, verifier, max_body, directory

    async def _send_json(self, send, status: int, doc: Dict[str, Any], extra=()) -> None:
        body = json.dumps(doc).encode("utf-8")
        headers = [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]
        headers += [(k.encode(), v.encode()) for k, v in extra]
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": body})

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            return await self.app(scope, receive, send)
        if scope.get("method") == "GET" and scope.get("path") == idm.WELL_KNOWN_PATH and self.directory:
            body = json.dumps(self.directory()).encode("utf-8")
            await send({"type": "http.response.start", "status": 200,
                        "headers": [(b"content-type", idm.DIRECTORY_MEDIA_TYPE.encode()),
                                    (b"cache-control", b"max-age=300")]})
            await send({"type": "http.response.body", "body": body})
            return

        chunks, size, more = [], 0, True
        while more:
            msg = await receive()
            if msg["type"] == "http.disconnect":
                return
            chunk = msg.get("body", b"")
            size += len(chunk)
            if size > self.max_body:
                return await self._send_json(send, 413, {"error": "body_too_large"})
            chunks.append(chunk)
            more = msg.get("more_body", False)
        body = b"".join(chunks)

        headers: Dict[str, str] = {}
        for k, v in scope.get("headers", []):
            name = k.decode("latin-1").lower()
            val = v.decode("latin-1")
            headers[name] = headers[name] + ", " + val if name in headers else val
        path = scope.get("path", "/")
        qs = scope.get("query_string", b"").decode("latin-1")
        ident = self.verifier.verify(scope.get("method", "GET"), path + ("?" + qs if qs else ""), headers, body)
        if ident.rejected:
            return await self._send_json(send, 401, {"error": "signature_rejected", "reason": ident.reason,
                                                     "help": "Unsigned requests are welcome (read, leave a message). "
                                                             "Signed requests must verify."},
                                         extra=[("accept-signature", ACCEPT_SIGNATURE)])

        scope = dict(scope)
        state = dict(scope.get("state") or {})
        state["agent_identity"] = ident
        scope["state"] = state
        sent = False

        async def replay():
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        return await self.app(scope, replay, send)


def identity_from_ctx(ctx: Any) -> Optional[idm.Identity]:
    """The Identity the middleware attached to this MCP request, or None (stdio, or no middleware)."""
    try:
        req = ctx.request_context.request
    except Exception:  # noqa: BLE001 - no request context outside HTTP
        return None
    scope = getattr(req, "scope", None)
    if not isinstance(scope, dict):
        return None
    ident = (scope.get("state") or {}).get("agent_identity")
    return ident if isinstance(ident, idm.Identity) else None
