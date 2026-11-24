"""The front door: every action an outside agent can take, decided by the consent rules.

Nothing in this module calls a language model. Caller text is length-capped, scrubbed of links
and control characters, checked against the hard floor, and then only stored for the owner to
read. It never becomes a prompt for our own agents.
"""
from __future__ import annotations

import re
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import yaml

from . import consent_core as cc
from . import identity as idm
from .facts import Facts

# The front door's hard floor: the consent network's floor plus commitments in the owner's name and
# anything that reaches for the owner's client data.
HARD_FLOOR = frozenset(cc.HARD_DENY | {"commitment", "client_data"})

# Words in caller text that pull an ask down to the hard floor, whatever action it came in on.
FLOOR_WORDS: List[Tuple[str, re.Pattern]] = [
    ("price", re.compile(r"\b(price[sd]?|pricing|cost[s]?|quote[sd]?|discount\w*|fee[s]?|rate card|how much|budget)\b|\$\s?\d", re.I)),
    ("payment", re.compile(r"\b(pay(ment|ing|s)?|invoice[sd]?|deposit|wire|charge (my|the) card|credit card|venmo|zelle|stripe)\b", re.I)),
    ("refund", re.compile(r"\b(refund\w*|chargeback)\b", re.I)),
    ("delete_data", re.compile(r"\b(delete|erase|wipe|purge)\b", re.I)),
    ("send_third_party", re.compile(r"\b(forward (this|it)|send (this|it|a message|an email|a text) to|email my|text my|message my|cc )\b", re.I)),
    ("client_data", re.compile(r"\b((client|customer|contact|member|patient|lead)s? (list|data|records?|emails?|numbers?|details)|your (clients|customers)'? ?(names|emails|data|info\w*)?|password\w*|api key\w*|credentials?)\b", re.I)),
    ("commitment", re.compile(r"\b(guarantee\w*|promise|sign (the|a|our) (contract|agreement)|commit to|exclusiv\w+)\b", re.I)),
]

FLOOR_REPLY = {
    "price": "f10", "pricing": "f10", "money": "f10", "payment": "f06", "refund": "f06",
    "delete_data": None, "send_third_party": "f06", "commitment": "f06", "client_data": "f07",
}

FLOOR_LABEL = {"price": "prices", "payment": "payments", "refund": "refunds", "delete_data": "deletion requests",
               "send_third_party": "messages to anyone else", "commitment": "commitments in the owner's name",
               "client_data": "requests for client data or credentials"}

ACTIONS = ("request_call", "ask_question", "leave_lead")
TOPICS = ("client_care", "missed_calls", "follow_up", "records", "front_door_for_my_business", "other")
WINDOWS = ("weekday_morning", "weekday_afternoon", "any")
NOTE_MAX = 280
_EMAIL = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}$")
_URL = re.compile(r"(https?://\S+|www\.\S+|\b\S+\.(com|net|org|io|ai|co|app|xyz)/\S*)", re.I)
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f\u200b-\u200f\u202a-\u202e\u2066-\u2069]")
_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._@()/-]{0,63}$")


class Refused(Exception):
    pass


def clean_note(text: Any) -> str:
    """Caller free text -> a short, link-free, single-paragraph string. Never shown to a model."""
    text = _CTRL.sub("", str(text or ""))
    text = _URL.sub("[link removed]", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:NOTE_MAX]


def floor_hit(*texts: str) -> Optional[str]:
    for t in texts:
        for kind, rx in FLOOR_WORDS:
            if t and rx.search(t):
                return kind
    return None


def label(value: Any, field: str) -> str:
    v = re.sub(r"\s+", " ", _CTRL.sub("", str(value or ""))).strip()
    if not _LABEL.match(v):
        raise Refused("%s must be 1-64 plain characters (letters, digits, space . _ @ ( ) / -)" % field)
    return v


class RateLimiter:
    """Sliding windows kept in memory, per key."""

    def __init__(self, clock: Callable[[], float]):
        self.clock = clock
        self.hits: Dict[Tuple[str, str], deque] = defaultdict(deque)

    def allow(self, bucket: str, key: str, limit: int, window: float) -> bool:
        now = self.clock()
        q = self.hits[(bucket, key)]
        while q and now - q[0] >= window:
            q.popleft()
        if len(q) >= limit:
            return False
        q.append(now)
        return True


class OwnerChannel:
    """Fictional owner channel for the prototype: one JSON line per message in a local file.
    In production this is ``hermes send -t telegram`` (the consent network's notify path)."""

    def __init__(self, path: Path, clock: Callable[[], float]):
        self.path, self.clock = Path(path), clock

    def send(self, text: str, **meta: Any) -> None:
        import json
        cc._ensure_dir(self.path.parent)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(dict(ts=cc.now_iso(self.clock()), text=text, **meta), ensure_ascii=False) + "\n")

    def read(self) -> List[Dict]:
        import json
        if not self.path.exists():
            return []
        return [json.loads(l) for l in self.path.read_text(encoding="utf-8").splitlines() if l.strip()]


class FrontDoor:
    def __init__(self, config_path: Path, state_dir: Path, clock: Callable[[], float] = time.time):
        self.config_path = Path(config_path)
        root = self.config_path.parent
        self.cfg = yaml.safe_load(self.config_path.read_text(encoding="utf-8"))
        b = self.cfg["business"]
        self.business = b
        self.facts = Facts.from_file(root / b["facts_file"], b["facts_url"])
        self.policies_dir = root / self.cfg.get("policies_dir", "policies")
        self.state_dir = Path(state_dir)
        cc._ensure_dir(self.state_dir)
        self.clock = clock
        self.pending = cc.Pending(self.state_dir)
        self.declines = cc.Declines(self.state_dir)
        self.receipts = cc.Receipts(self.state_dir, side=b["door_id"])
        self.owner = OwnerChannel(self.state_dir / "owner_channel.jsonl", clock)
        self.inbox = OwnerChannel(self.state_dir / "inbox.jsonl", clock)
        self.daily = cc.JsonState(self.state_dir / "daily.json")
        self.limits = self.cfg.get("limits", {})
        self.rate = RateLimiter(clock)
        ident = self.cfg.get("identity") or {}
        self.min_trust: Dict[str, str] = dict(ident.get("min_trust") or {})
        self.door_key: Optional[idm.AgentKey] = None
        self.door_key_url = str(ident.get("door_key_url") or "")
        if ident.get("sign_receipts"):
            kpath = self.state_dir / "door_ed25519.key"   # git-ignored state; never in the repo
            if not kpath.exists():
                idm.AgentKey.generate().to_file(kpath)
            self.door_key = idm.AgentKey.from_file(kpath)

    def door_directory(self) -> Dict[str, Any]:
        """The door's own key directory (what it would publish so callers can check its receipts)."""
        if not self.door_key:
            return {"keys": []}
        return idm.directory([self.door_key], card={"client_name": "%s front door" % self.business["name"],
                                                    "contacts": ["mailto:" + self.business["email"]]})

    # -- identity and policy ---------------------------------------------------------------
    def caller(self, caller_agent: Any, caller_model: Any, acting_for: Any, caller_key: Any = "",
               identity: Optional[idm.Identity] = None) -> Dict[str, str]:
        """Who is knocking. Names are self-reported; ``identity`` comes only from the HTTP layer's
        signature check (never from tool arguments), so a caller cannot claim a domain by typing it."""
        c = {"caller_agent": label(caller_agent, "caller_agent"),
             "caller_model": label(caller_model, "caller_model"),
             "acting_for": label(acting_for, "acting_for"),
             "identity": "self_reported", "policy": "public"}
        ident = identity or idm.unsigned("no_http_signature")
        # The principal is what rate caps, open questions and remembered no's attach to. A verified
        # domain cannot shed a no by renaming its agent; a self-reported name can only rename itself.
        c["principal"] = c["caller_agent"]
        c["identity_label"] = ident.label
        for k, v in ident.receipt_fields().items():
            if k in ("verified_domain", "signature_agent", "keyid", "request_sig_sha256"):
                c[k] = v
        if ident.level == idm.SIGNED:
            c["identity"], c["principal"] = "signed_no_domain", "key:" + ident.keyid
        elif ident.level in (idm.DOMAIN_VERIFIED, idm.PARTNER):
            # Partner status is the door owner's list, checked here, not anything the caller sent.
            slug = self.partner_domains().get(ident.domain, "")
            c["identity"] = idm.PARTNER if slug else idm.DOMAIN_VERIFIED
            c["principal"], c["policy"] = ident.domain, slug or "verified"
            if slug:
                c["identity_label"] = "partner: %s" % ident.domain
        slug = cc.safe_name(re.sub(r"[^A-Za-z0-9_.-]+", "-", c["caller_agent"]).strip("-"))
        if slug and caller_key and c["identity"] in ("self_reported", "signed_no_domain"):
            pol = cc.load_policy(self.policies_dir / "partners", slug)
            raw = yaml.safe_load(Path(pol.source).read_text()) if pol else None
            if raw and raw.get("key_sha256") and cc.sha256_text(str(caller_key)) == raw["key_sha256"]:
                c["identity"], c["policy"], c["identity_label"] = "verified_partner", slug, "partner key: " + slug
        return c

    def partner_domains(self) -> Dict[str, str]:
        """domain -> partner policy slug, from partners/*.yaml files that name a ``domain``."""
        out: Dict[str, str] = {}
        pdir = self.policies_dir / "partners"
        if pdir.is_dir():
            for f in sorted(pdir.glob("*.yaml")):
                if f.is_symlink():
                    continue
                try:
                    raw = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
                except yaml.YAMLError:
                    continue
                dom = str(raw.get("domain") or "").strip().lower()
                if dom and raw.get("peer") == f.stem:
                    out[dom] = f.stem
        return out

    def trust_rank(self, c: Dict[str, str]) -> int:
        return {"self_reported": 0, "signed_no_domain": 1, "domain_verified": 2, "partner": 3,
                "verified_partner": 3}.get(c.get("identity", ""), 0)

    def policy_for(self, c: Dict[str, str]) -> cc.Policy:
        if c["policy"] not in ("public", "verified"):
            pol = cc.load_policy(self.policies_dir / "partners", c["policy"])
            if pol:
                return pol
        if c["policy"] == "verified":
            pol = cc.load_policy(self.policies_dir, "verified")
            if pol:
                return pol
        pol = cc.load_policy(self.policies_dir, "public")
        if pol is None:  # no public policy -> the door is closed to strangers
            return cc.Policy("public", {"deny": list(ACTIONS)})
        return pol

    def _receipt(self, c: Dict[str, str], **fields: Any) -> Dict[str, Any]:
        idf = {k: c[k] for k in ("identity_label", "principal", "verified_domain", "signature_agent", "keyid",
                                 "request_sig_sha256") if c.get(k)}
        return self.receipts.append(self.clock(), direction="in", peer=c["policy"], owner=self.business["owner"],
                                    caller_agent=c["caller_agent"], caller_model=c["caller_model"],
                                    acting_for=c["acting_for"], identity=c["identity"], **idf, **fields)

    def _public_receipt(self, r: Dict[str, Any]) -> Dict[str, Any]:
        out = {k: r[k] for k in ("seq", "ts", "ask_id", "ask_type", "decision", "reason", "text_sha256", "prev", "hash",
                                 "identity", "identity_label", "verified_domain", "request_sig_sha256") if k in r}
        if self.door_key:
            out = idm.sign_receipt(self.door_key, self.door_key_url, out)
        return out

    # -- read path -------------------------------------------------------------------------
    def read_allowed(self, key: str) -> bool:
        lim = self.limits
        return self.rate.allow("read", key or "anon", int(lim.get("reads_per_minute", 60)), 60.0)

    def list_facts(self) -> Dict[str, Any]:
        return {"business": self.business["name"], "source": self.facts.source_url,
                "page_sha256": self.facts.page_sha256, "summary": self.facts.byline,
                "facts": [{"id": f["id"], "question": f["question"], "answer": f["answer"], "links": f["links"]}
                          for f in self.facts.items],
                "note": "Every answer is the page's own text, word for word. Nothing here is generated."}

    def lookup(self, question: str) -> Dict[str, Any]:
        q = clean_note(question)
        hit = self.facts.search(q)
        if not hit:
            return {"found": False, "answer": None,
                    "note": "The facts page does not answer this. Use ask_question to put it to the owner."}
        return {"found": True, "fact_id": hit["id"], "question": hit["question"], "answer": hit["answer"],
                "links": hit["links"], "source": hit["source"], "match_score": hit["match_score"]}

    # -- act path --------------------------------------------------------------------------
    def act(self, action: str, caller: Dict[str, str], fields: Dict[str, Any]) -> Dict[str, Any]:
        """One decision for one ask. Returns a dict the caller sees; never the owner's channel."""
        if action not in ACTIONS:
            raise Refused("unknown action")
        c = caller
        lim = self.limits
        note = clean_note(fields.get("note"))
        topic = fields.get("topic") or "other"
        if topic not in TOPICS:
            raise Refused("topic must be one of: " + ", ".join(TOPICS))
        contact = str(fields.get("contact_email") or "").strip()
        if not _EMAIL.match(contact):
            raise Refused("contact_email must be a plain email address")
        window = fields.get("preferred_window") or "any"
        if window not in WINDOWS:
            raise Refused("preferred_window must be one of: " + ", ".join(WINDOWS))
        name = label(fields.get("name") or c["acting_for"], "name")
        body = "action=%s topic=%s window=%s name=%s contact=%s note=%s" % (action, topic, window, name, contact, note)
        who = c.get("principal") or c["caller_agent"]
        ask_id = cc.derived_ask_id(who + "|" + c["acting_for"], action, body)
        text_hash = cc.sha256_text(cc.normalize_text(body))
        base = dict(ask_id=ask_id, text_sha256=text_hash, summary=cc.one_line("%s from %s for %s" % (action, c["caller_agent"], c["acting_for"])))

        def out(decision: str, reason: str, message: str, rec: Dict[str, Any], **extra: Any) -> Dict[str, Any]:
            word = {"allow": "allowed", "deny": "denied", "ask_owner": "waiting"}[decision]
            return dict({"request_id": ask_id, "status": word, "reason": reason, "message": message,
                         "receipt": self._public_receipt(rec)}, **extra)

        # 1. rate caps (per caller agent and per person acted for)
        for key in (who, c["acting_for"]):
            if not self.rate.allow("act", key, int(lim.get("actions_per_hour", 5)), 3600.0):
                rec = self._receipt(c, event="ask", ask_type=action, decision=cc.DENY, reason="rate_limited", **base)
                return out(cc.DENY, "rate_limited", "Too many requests from this caller. Try again in an hour.", rec)

        # 2. hard floor: by caller words, never openable by any allow-list
        floor = floor_hit(note, fields.get("question") or "")
        if floor:
            rec = self._receipt(c, event="ask", ask_type=floor, decision=cc.DENY, reason="always_denied", **base)
            fact = self.facts.get(FLOOR_REPLY.get(floor) or "") if FLOOR_REPLY.get(floor) else None
            msg = ("This door does not handle %s. Through this door an agent never moves money, quotes or sets "
                   "prices, sends to anyone else, deletes data, shares client data, or makes commitments in the "
                   "owner's name." % FLOOR_LABEL.get(floor, floor.replace("_", " ")))
            extra = {"page_says": fact["answer"], "source": fact["source"]} if fact else {
                "page_says": None, "contact": self.business["email"]}
            return out(cc.DENY, "always_denied", msg, rec, **extra)

        # 2b. trust floor: some asks need a signature from a domain the owner stands behind
        need = self.min_trust.get(action)
        if need and self.trust_rank(c) < idm.RANK.get(need, 99):
            rec = self._receipt(c, event="ask", ask_type=action, decision=cc.DENY, reason="needs_" + need, **base)
            return out(cc.DENY, "needs_" + need,
                       "This door takes %s only from an agent whose owner's domain vouches for it (Web Bot Auth: "
                       "sign the request, publish your key at https://<your-domain>%s). You can still leave a "
                       "message with leave_lead." % (action.replace("_", " "), idm.WELL_KNOWN_PATH), rec)

        # 3. the owner already answered this exact ask
        prior = self.pending.get(ask_id)
        if prior:
            return self._resume(c, prior, base, out)

        pol = self.policy_for(c)
        decision, reason = pol.decide(action)
        if decision == cc.DENY:
            rec = self._receipt(c, event="ask", ask_type=action, decision=cc.DENY, reason=reason, **base)
            return out(cc.DENY, reason, "This door does not take that request from this caller.", rec)
        if decision == cc.ALLOW:
            rec = self._receipt(c, event="ask", ask_type=action, decision=cc.ALLOW, reason=reason, **base)
            return out(cc.ALLOW, reason, self._execute(action, c, name, contact, topic, window, note, ask_id), rec)

        # 4. remembered no (same caller + person, same action, similar words)
        prev_no = self.declines.match(peer=who + "|" + c["acting_for"], ask_type=action, body=body,
                                      threshold=float(lim.get("decline_similarity", 0.6)),
                                      expire_days=float(lim.get("decline_days", 90)), now=self.clock())
        if prev_no:
            rec = self._receipt(c, event="ask", ask_type=action, decision=cc.DENY, reason="remembered_no", **base)
            return out(cc.DENY, "remembered_no", "The owner already declined this request.", rec)

        # 5. caps on owner questions: per caller open asks, and per day overall
        now = self.clock()
        if self.pending.open_for_peer(who, now, float(lim.get("pending_ttl_hours", 72)) * 3600) >= pol.max_pending:
            rec = self._receipt(c, event="ask", ask_type=action, decision=cc.DENY, reason="too_many_pending", **base)
            return out(cc.DENY, "too_many_pending", "This caller already has requests waiting on the owner.", rec)
        day = cc.short_date(now)
        cap = int(lim.get("owner_questions_per_day", 10))
        took = self.daily.update(lambda d: (d.__setitem__(day, d.get(day, 0) + 1), d[day] <= cap)[1])
        if not took:
            rec = self._receipt(c, event="ask", ask_type=action, decision=cc.DENY, reason="daily_owner_cap", **base)
            return out(cc.DENY, "daily_owner_cap", "The owner's question limit for today is reached. Try tomorrow.", rec)

        code = cc.owner_code(ask_id, who)
        self.pending.create({"key": ask_id, "ask_id": ask_id, "peer": who, "code": code,
                             "status": "pending", "created": now, "action": action, "caller": c,
                             "fields": {"name": name, "contact": contact, "topic": topic, "window": window, "note": note},
                             "body": body, "text_sha256": text_hash})
        self.owner.send(
            "Front door: %s (model %s, %s) asks to %s for %s.\nTopic: %s. Window: %s. Contact: %s.\n"
            "Their words, unverified: \"%s\"\nReply: consent yes %s  /  consent no %s"
            % (c["caller_agent"], c["caller_model"], c.get("identity_label") or c["identity"].replace("_", " "),
               action.replace("_", " "),
               name, topic, window, contact, note or "(none)", code, code),
            code=code, ask_id=ask_id)
        rec = self._receipt(c, event="ask", ask_type=action, decision=cc.ASK_OWNER, reason=reason, **base)
        return out(cc.ASK_OWNER, reason, "Sent to the owner as one yes/no question. Call check_request with this "
                   "request_id later. Nothing happens until the owner answers.", rec)

    def _resume(self, c, prior, base, out) -> Dict[str, Any]:
        status = prior.get("status")
        if status == "approved":
            self.pending.set(prior["ask_id"], status="used")
            f = prior["fields"]
            rec = self._receipt(c, event="result", ask_type=prior["action"], decision=cc.ALLOW, reason="owner_approved", **base)
            return out(cc.ALLOW, "owner_approved",
                       self._execute(prior["action"], c, f["name"], f["contact"], f["topic"], f["window"], f["note"], prior["ask_id"]), rec)
        if status == "used":
            rec = self._receipt(c, event="ask", ask_type=prior["action"], decision=cc.ALLOW, reason="already_done", **base)
            return out(cc.ALLOW, "already_done", "Already done. Nothing new was recorded.", rec)
        if status == "declined":
            rec = self._receipt(c, event="result", ask_type=prior["action"], decision=cc.DENY, reason="owner_declined", **base)
            return out(cc.DENY, "owner_declined", "The owner declined this request.", rec)
        rec = self._receipt(c, event="ask", ask_type=prior["action"], decision=cc.ASK_OWNER, reason="still_waiting", **base)
        return out(cc.ASK_OWNER, "still_waiting", "Still waiting on the owner.", rec)

    def check(self, request_id: str, caller: Dict[str, str]) -> Dict[str, Any]:
        rid = str(request_id or "").strip().upper()
        prior = self.pending.get(rid)
        pc = prior.get("caller", {}) if prior else {}
        if not prior or (pc.get("principal") or pc.get("caller_agent")) != (caller.get("principal") or caller["caller_agent"]):
            raise Refused("no such request for this caller")
        base = dict(ask_id=rid, text_sha256=prior["text_sha256"], summary=cc.one_line("check_request " + rid))

        def out(decision, reason, message, rec, **extra):
            word = {"allow": "allowed", "deny": "denied", "ask_owner": "waiting"}[decision]
            return dict({"request_id": rid, "status": word, "reason": reason, "message": message,
                         "receipt": self._public_receipt(rec)}, **extra)
        return self._resume(caller, prior, base, out)

    def _execute(self, action, c, name, contact, topic, window, note, ask_id) -> str:
        """The only side effect: a line in the owner's local inbox. No email, text or calendar write."""
        self.inbox.send("%s: %s via %s (%s). Topic %s, window %s, contact %s. Note: %s"
                        % (action, name, c["caller_agent"], c["caller_model"], topic, window, contact, note or "-"),
                        ask_id=ask_id, action=action)
        b = self.business
        if action == "request_call":
            return ("Recorded for %s. If the work fits, %s takes the call. To pick a time now: %s"
                    % (b["name"], b["founder"], b["booking_url"]))
        if action == "leave_lead":
            return "Recorded. An AI agent reads every brief first and replies the way you ask."
        return "Recorded. The owner will answer by email at the contact address given."

    # -- owner side ------------------------------------------------------------------------
    def owner_answer(self, code: str, yes: bool, owner: str = "") -> Dict[str, Any]:
        rec = self.pending.by_code(code)
        if not rec or rec.get("status") != "pending":
            raise Refused("no open request with that code")
        owner = owner or self.business["owner"]
        self.pending.set(rec["ask_id"], status="approved" if yes else "declined", answered=self.clock())
        if not yes:
            self.declines.add(peer=(rec["caller"].get("principal") or rec["caller"]["caller_agent"]) + "|"
                              + rec["caller"]["acting_for"],
                              ask_type=rec["action"], body=rec["body"], ask_id=rec["ask_id"], owner=owner, now=self.clock())
        self._receipt(rec["caller"], event="owner_answer", ask_id=rec["ask_id"], ask_type=rec["action"],
                      text_sha256=rec["text_sha256"], decision=cc.ALLOW if yes else cc.DENY,
                      reason="owner_approved" if yes else "owner_declined", decided_by="owner:" + owner)
        return {"ask_id": rec["ask_id"], "answer": "yes" if yes else "no"}
