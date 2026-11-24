// Agent front door, as a Cloudflare Worker (MCP over streamable HTTP, stateless transport).
//
// Read tools (no storage touched): door_rules, list_facts, lookup_fact. Facts are the
// deployaxiom.com/facts page's own words, bundled at deploy time by worker/build_facts.py.
//
// Act tools: request_call, ask_question, leave_lead, check_request. Each act is decided by the
// owner's consent rules inside one SQLite-backed Durable Object (Workers Free): hard floor first,
// then remembered no, caps, then ONE yes/no question for the owner. The door never sends anything
// itself and never connects to the owner's machine: the owner's machine pulls questions from
// /owner/pull and pushes answers to /owner/answer, with a bearer token whose sha256 is a Worker
// secret. Caller text is length-capped, link-stripped, never given to a model, and every decision
// writes a hash-chained receipt; the caller gets its copy in every answer.

import { DurableObject } from "cloudflare:workers";
import { createHash, timingSafeEqual } from "node:crypto";
import BUNDLE from "./facts.json";
import CFG from "./door.config.json";
import * as ID from "./identity.js";

const VERSION = "0.3.0";
const IDC = CFG.identity || { enabled: false };
const DIR_CACHE = new Map(); // key directories, per isolate, at most 5 minutes (identity.js)
const PROTOCOLS = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];
const MAX_BODY = 16 * 1024;
const STOP = new Set(BUNDLE.stop);
const SYN = BUNDLE.syn;
const SYN_VALUES = new Set(Object.values(SYN));
const LIM = CFG.limits;
const TOPICS = ["client_care", "missed_calls", "follow_up", "records", "front_door_for_my_business", "other"];
const WINDOWS = ["weekday_morning", "weekday_afternoon", "any"];
const BOOKING = (BUNDLE.facts.find((f) => f.id === CFG.booking_fact)?.links || []).find((l) => l.startsWith("https://")) || BUNDLE.source;

const RULES =
  "This is " + BUNDLE.business + "'s public front door for AI agents. It is open to any model.\n" +
  "Read: list_facts and lookup_fact return the business's own facts page (" + BUNDLE.source + "), word for word. " +
  "Nothing is generated and no model reads what you send.\n" +
  "Act: request_call, ask_question and leave_lead go through the owner's rules. A lead is recorded for the owner. " +
  "A call request, or a question the page does not answer, becomes one yes/no question to the owner; nothing happens " +
  "until he answers, and you collect the answer with check_request. A no is remembered and he is not asked again.\n" +
  "Always refused, for everyone: prices, payments, refunds, deleting data, client data or passwords, sending messages " +
  "to anyone else, and commitments in the owner's name.\n" +
  "Say who you are: caller_agent, caller_model and acting_for are recorded as self reported. To be shown to the owner as " +
  "'verified: <your domain>', sign each HTTP request with Web Bot Auth (" + ID.STANDARD_URL + "): RFC 9421 Ed25519 over " +
  "@method, @authority, @path, content-digest and signature-agent, key published at https://<your-domain>" + ID.WELL_KNOWN_PATH +
  ". Unsigned callers can still do everything here; the owner sees them as self reported. A signature that fails is refused. Every answer carries a " +
  "receipt (hash chained) so both sides can prove what happened.\n" +
  "Limits: notes and questions are cut to " + BUNDLE.note_max + " characters with links removed; the owner takes at most " +
  LIM.owner_messages_per_day + " questions or leads a day across all callers; requests are rate limited.";

// --- text rules, ported from the Python door (agent_front_door/door.py and facts.py) ------------
const CTRL = /[\x00-\x08\x0b-\x1f\x7f\u200b-\u200f\u202a-\u202e\u2066-\u2069]/g;
const URLRX = /(https?:\/\/\S+|www\.\S+|\b\S+\.(com|net|org|io|ai|co|app|xyz)\/\S*)/gi;
const LABEL = /^[A-Za-z0-9][A-Za-z0-9 ._@()\/-]{0,63}$/;
const EMAIL = /^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}$/;
const FLOOR_WORDS = [
  ["price", /\b(price[sd]?|pricing|cost[s]?|quote[sd]?|discount\w*|fee[s]?|rate card|how much|budget)\b|\$\s?\d/i],
  ["payment", /\b(pay(ment|ing|s)?|invoice[sd]?|deposit|wire|charge (my|the) card|credit card|venmo|zelle|stripe)\b/i],
  ["refund", /\b(refund\w*|chargeback)\b/i],
  ["delete_data", /\b(delete|erase|wipe|purge)\b/i],
  ["send_third_party", /\b(forward (this|it)|send (this|it|a message|an email|a text) to|email my|text my|message my|cc )\b/i],
  ["client_data", /\b((client|customer|contact|member|patient|lead)s? (list|data|records?|emails?|numbers?|details)|your (clients|customers)'? ?(names|emails|data|info\w*)?|password\w*|api key\w*|credentials?)\b/i],
  ["commitment", /\b(guarantee\w*|promise|sign (the|a|our) (contract|agreement)|commit to|exclusiv\w+)\b/i],
];

export function cleanNote(text) {
  let t = String(text ?? "").replace(CTRL, "");
  t = t.replace(URLRX, "[link removed]");
  t = t.replace(/\s+/g, " ").trim();
  return Array.from(t).slice(0, BUNDLE.note_max).join("");
}

export function floorHit(...texts) {
  for (const t of texts) {
    if (!t) continue;
    for (const [kind, rx] of FLOOR_WORDS) if (rx.test(t)) return kind;
  }
  return null;
}

class Refused extends Error {}

function label(value, field) {
  const v = String(value ?? "").replace(CTRL, "").replace(/\s+/g, " ").trim();
  if (!LABEL.test(v)) throw new Refused(field + " must be 1-64 plain characters (letters, digits, space . _ @ ( ) / -)");
  return v;
}

const words = (s) => (String(s || "").toLowerCase().match(/[a-z0-9]+/g) || []);
const tokens = (s) => new Set(words(s).filter((w) => !STOP.has(w) && w.length > 1));

const INDEX = BUNDLE.facts.map((f) => {
  const head = tokens(f.question);
  for (const w of words(f.question)) if (SYN_VALUES.has(w)) head.add(w);
  const body = tokens(f.answer);
  for (const w of words(f.answer)) body.add(w);
  return { f, head, body };
});

export function search(question, minScore = 0.5) {
  const q = tokens(question);
  if (!q.size) return null;
  let best = null, bestScore = 0;
  for (const { f, head, body } of INDEX) {
    let hits = 0;
    for (const w of q) {
      const forms = [w, SYN[w] ?? w, w.replace(/s+$/, "")];
      if (forms.some((x) => head.has(x))) hits += 1;
      else if (forms.some((x) => body.has(x))) hits += 0.5;
    }
    const score = hits / q.size;
    if (score > bestScore) { best = f; bestScore = score; }
  }
  if (!best || bestScore < minScore) return null;
  return { ...best, match_score: Math.round(bestScore * 100) / 100 };
}

// --- consent helpers (same shapes as hermes-consent-network core.py) ---------------------------
const sha256 = (s) => createHash("sha256").update(String(s), "utf8").digest("hex");
const normalize = (t) => String(t || "").toLowerCase().replace(/[^a-z0-9 ]+/g, " ").replace(/\s+/g, " ").trim();
const askIdFor = (peer, action, body) => sha256(peer + "\0" + action + "\0" + normalize(body)).slice(0, 10).toUpperCase();
function ownerCode(askId, peer) {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const d = createHash("sha256").update(peer + "\0" + askId, "utf8").digest();
  let s = "";
  for (let i = 0; i < 6; i++) s += alphabet[d[i] % alphabet.length];
  return s;
}
function jaccard(a, b) {
  const sa = new Set(a.split(" ").filter(Boolean)), sb = new Set(b.split(" ").filter(Boolean));
  if (!sa.size && !sb.size) return 1;
  let inter = 0;
  for (const x of sa) if (sb.has(x)) inter++;
  return inter / (new Set([...sa, ...sb]).size || 1);
}
export function canon(o) {
  return JSON.stringify(Object.keys(o).sort().reduce((a, k) => ((a[k] = o[k]), a), {}));
}
const nowIso = (t) => new Date(t * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");
const localDay = (t) => new Intl.DateTimeFormat("en-CA", { timeZone: CFG.timezone, year: "numeric", month: "2-digit", day: "2-digit" }).format(new Date(t * 1000));
const GENESIS = "0".repeat(64);

const FLOOR_MSG = (kind) =>
  "This door does not handle " + (BUNDLE.floor_label[kind] || kind.replace(/_/g, " ")) + ". Through this door an agent never " +
  "moves money, quotes or sets prices, sends to anyone else, deletes data, shares client data, or makes commitments in the owner's name.";

const DONE_MSG = {
  request_call: "Recorded for " + BUNDLE.business + ". If the work fits, " + CFG.founder + " takes the call. To pick a time now: " + BOOKING,
  ask_question: "Recorded for " + BUNDLE.business + ". The owner said yes to this question and answers it by email at the contact address given.",
  leave_lead: "Recorded for " + BUNDLE.business + ". The owner reads it himself; no AI reads your words.",
};

// --- the stateful half: one Durable Object holds asks, answers, declines, caps and receipts -----
export class DoorState extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    ctx.blockConcurrencyWhile(async () => {
      this.sql.exec(`
        CREATE TABLE IF NOT EXISTS receipts (seq INTEGER PRIMARY KEY, record TEXT NOT NULL, prev TEXT NOT NULL, hash TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS asks (ask_id TEXT PRIMARY KEY, code TEXT, kind TEXT, action TEXT, peer TEXT,
          caller_agent TEXT, status TEXT, created REAL, answered REAL, notified REAL, body TEXT, text_sha256 TEXT,
          caller TEXT, fields TEXT);
        CREATE INDEX IF NOT EXISTS asks_code ON asks(code);
        CREATE TABLE IF NOT EXISTS declines (id INTEGER PRIMARY KEY AUTOINCREMENT, peer TEXT, action TEXT, norm TEXT, ts REAL, ask_id TEXT);
        CREATE TABLE IF NOT EXISTS acts (ts REAL, key TEXT);
        CREATE TABLE IF NOT EXISTS daily (day TEXT PRIMARY KEY, n INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS nonces (k TEXT PRIMARY KEY, until REAL NOT NULL);
      `);
    });
  }

  rows(q, ...p) { return this.sql.exec(q, ...p).toArray(); }

  // Web Bot Auth replay guard: each (agent URL, nonce) is accepted once, until its signature expires.
  async nonce(agentUrl, nonce, until) {
    const now = Date.now() / 1000;
    this.sql.exec("DELETE FROM nonces WHERE until < ?", now);
    const k = sha256(String(agentUrl) + "\0" + String(nonce));
    if (this.rows("SELECT k FROM nonces WHERE k = ?", k).length) return false;
    this.sql.exec("INSERT INTO nonces (k, until) VALUES (?, ?)", k, Number(until) || now + 360);
    return true;
  }

  expire(now) {
    this.sql.exec("UPDATE asks SET status='expired' WHERE status='pending' AND created < ?", now - LIM.pending_ttl_hours * 3600);
  }

  receipt(fields) {
    const last = this.rows("SELECT seq, hash FROM receipts ORDER BY seq DESC LIMIT 1")[0];
    const now = Date.now() / 1000;
    const rec = { seq: last ? last.seq + 1 : 1, ts: nowIso(now), side: CFG.door_id, owner: CFG.owner, ...fields,
                  prev: last ? last.hash : GENESIS };
    const hash = sha256(rec.prev + "\n" + canon(rec));
    this.sql.exec("INSERT INTO receipts (seq, record, prev, hash) VALUES (?, ?, ?, ?)", rec.seq, canon(rec), rec.prev, hash);
    return { ...rec, hash };
  }

  static pub(r) {
    const out = {};
    for (const k of ["seq", "ts", "ask_id", "ask_type", "decision", "reason", "text_sha256", "identity", "identity_label",
                     "verified_domain", "request_sig_sha256", "prev", "hash"]) if (k in r) out[k] = r[k];
    return out;
  }

  out(askId, decision, reason, message, rec, extra = {}) {
    const status = { allow: "allowed", deny: "denied", ask_owner: "waiting" }[decision];
    return { request_id: askId, status, reason, message, receipt: DoorState.pub(rec), ...extra };
  }

  // One decision for one ask. c = callerOf(): self-reported names plus the identity the HTTP layer verified.
  // The principal (verified domain, or the self-reported agent name) is what caps and remembered no's
  // attach to, so a verified domain cannot shed a no by renaming its agent.
  async act(action, c, f, ipKey) {
    const now = Date.now() / 1000;
    this.expire(now);
    const principal = c.principal || c.caller_agent;
    const peer = principal + "|" + c.acting_for;
    const body = `action=${action} topic=${f.topic} window=${f.window} name=${f.name} contact=${f.contact} note=${f.note}`;
    const askId = askIdFor(peer, action, body);
    const textSha = sha256(normalize(body));
    const who = { caller_agent: c.caller_agent, caller_model: c.caller_model, acting_for: c.acting_for, identity: c.identity,
                  identity_label: c.identity_label || "self reported" };
    for (const k of ["verified_domain", "signature_agent", "keyid", "request_sig_sha256"]) if (c[k]) who[k] = c[k];
    const base = { ask_id: askId, text_sha256: textSha, ...who };
    const deny = (reason, msg, type = action, extra = {}) =>
      this.out(askId, "deny", reason, msg, this.receipt({ event: "ask", ask_type: type, decision: "deny", reason, ...base }), extra);

    // 1. rate caps: per caller IP, per caller agent, per person acted for (rolling hour)
    this.sql.exec("DELETE FROM acts WHERE ts < ?", now - 3600);
    const keys = [["ip:" + ipKey, LIM.acts_per_hour_per_ip], ["agent:" + principal, LIM.acts_per_hour_per_caller],
                  ["person:" + c.acting_for, LIM.acts_per_hour_per_person]];
    for (const [k, lim] of keys) {
      const n = this.rows("SELECT COUNT(*) AS n FROM acts WHERE key = ?", k)[0].n;
      if (n >= lim) return deny("rate_limited", "Too many requests from this caller. Try again in an hour.");
    }
    for (const [k] of keys) this.sql.exec("INSERT INTO acts (ts, key) VALUES (?, ?)", now, k);

    // 2. hard floor, by the caller's own words; no allow-list opens it
    const floor = floorHit(f.note, f.name, c.acting_for);
    if (floor) {
      const ref = BUNDLE.floor_reply[floor] ? BUNDLE.facts.find((x) => x.id === BUNDLE.floor_reply[floor]) : null;
      return deny("always_denied", FLOOR_MSG(floor), floor, ref ? { page_says: ref.answer, source: BUNDLE.source } : { page_says: null });
    }

    // 2b. trust floor: the owner can require a verified domain for an ask (identity.min_trust; empty = no floor)
    const need = (IDC.min_trust || {})[action];
    if (need && (ID.RANK[c.identity] ?? 0) < (ID.RANK[need] ?? 99))
      return deny("needs_" + need, "This door takes " + action.replace("_", " ") + " only from an agent whose owner's domain " +
                  "vouches for it. Sign the request with Web Bot Auth (" + ID.STANDARD_URL + ") and publish your key at " +
                  "https://<your-domain>" + ID.WELL_KNOWN_PATH + ". You can still leave a message with leave_lead.");

    // 3. the owner already answered this exact ask
    let prior = this.rows("SELECT * FROM asks WHERE ask_id = ?", askId)[0];
    if (prior && prior.status === "expired") { this.sql.exec("DELETE FROM asks WHERE ask_id = ?", askId); prior = null; }
    if (prior) return this.resume(prior, base);

    // 4. policy
    const pol = CFG.policy;
    if (pol.deny.includes(action) || (!pol.allow.includes(action) && !pol.ask_owner.includes(action)))
      return deny("policy_deny", "This door does not take that request from this caller.");

    // 5. remembered no (same caller + person, same action, similar words), then open-question cap
    if (!pol.allow.includes(action)) {
      const norm = normalize(body);
      const since = now - LIM.decline_days * 86400;
      for (const d of this.rows("SELECT norm FROM declines WHERE peer = ? AND action = ? AND ts >= ?", peer, action, since))
        if (jaccard(norm, d.norm) >= LIM.decline_similarity) return deny("remembered_no", "The owner already declined this request.");
      const open = this.rows("SELECT COUNT(*) AS n FROM asks WHERE caller_agent = ? AND status = 'pending'", c.caller_agent)[0].n;
      if (open >= LIM.max_pending_per_caller)
        return deny("too_many_pending", "This caller already has requests waiting on the owner.");
    }

    // 6. the owner's daily cap (questions and leads together)
    const day = localDay(now);
    const used = this.rows("SELECT n FROM daily WHERE day = ?", day)[0]?.n || 0;
    if (used >= LIM.owner_messages_per_day)
      return deny("daily_owner_cap", "The owner's limit for today is reached. Try tomorrow.");
    this.sql.exec("INSERT INTO daily (day, n) VALUES (?, 1) ON CONFLICT(day) DO UPDATE SET n = n + 1", day);

    const fields = JSON.stringify(f), caller = JSON.stringify(who);
    if (pol.allow.includes(action)) {
      this.sql.exec("INSERT INTO asks (ask_id, code, kind, action, peer, caller_agent, status, created, body, text_sha256, caller, fields) " +
                    "VALUES (?, NULL, 'lead', ?, ?, ?, 'used', ?, ?, ?, ?, ?)", askId, action, peer, c.caller_agent, now, body, textSha, caller, fields);
      const rec = this.receipt({ event: "ask", ask_type: action, decision: "allow", reason: "allow_list", ...base });
      return this.out(askId, "allow", "allow_list", DONE_MSG[action], rec);
    }
    const code = ownerCode(askId, c.caller_agent);
    this.sql.exec("INSERT INTO asks (ask_id, code, kind, action, peer, caller_agent, status, created, body, text_sha256, caller, fields) " +
                  "VALUES (?, ?, 'question', ?, ?, ?, 'pending', ?, ?, ?, ?, ?)", askId, code, action, peer, c.caller_agent, now, body, textSha, caller, fields);
    const rec = this.receipt({ event: "ask", ask_type: action, decision: "ask_owner", reason: "ask_owner", ...base });
    return this.out(askId, "ask_owner", "ask_owner", "Sent to the owner as one yes/no question. Call check_request with this " +
                    "request_id later. Nothing happens until the owner answers.", rec);
  }

  resume(prior, base) {
    const st = prior.status, action = prior.action;
    const r = (event, decision, reason) => this.receipt({ event, ask_type: action, decision, reason, ...base });
    if (st === "approved") {
      this.sql.exec("UPDATE asks SET status = 'used' WHERE ask_id = ?", prior.ask_id);
      return this.out(prior.ask_id, "allow", "owner_approved", DONE_MSG[action], r("result", "allow", "owner_approved"));
    }
    if (st === "used")
      return this.out(prior.ask_id, "allow", "already_done", "Already done. Nothing new was recorded.", r("ask", "allow", "already_done"));
    if (st === "declined")
      return this.out(prior.ask_id, "deny", "owner_declined", "The owner declined this request.", r("result", "deny", "owner_declined"));
    if (st === "expired")
      return this.out(prior.ask_id, "deny", "expired", "The owner did not answer in time. Ask again if it still matters.", r("result", "deny", "expired"));
    return this.out(prior.ask_id, "ask_owner", "still_waiting", "Still waiting on the owner.", r("ask", "ask_owner", "still_waiting"));
  }

  async check(requestId, callerAgent) {
    this.expire(Date.now() / 1000);
    const rid = String(requestId || "").trim().toUpperCase();
    const prior = this.rows("SELECT * FROM asks WHERE ask_id = ?", rid)[0];
    if (!prior || prior.caller_agent !== callerAgent) return { status: "refused", message: "no such request for this caller" };
    const who = JSON.parse(prior.caller);
    return this.resume(prior, { ask_id: rid, text_sha256: prior.text_sha256, ...who });
  }

  // --- owner side (reached only with the owner token; the owner's machine pulls) ---
  async ownerPull() {
    const now = Date.now() / 1000;
    this.expire(now);
    // Keep caller words no longer than the decline memory needs them.
    this.sql.exec("UPDATE asks SET fields = '{}' WHERE created < ? AND fields != '{}'", now - LIM.decline_days * 86400);
    const items = this.rows("SELECT ask_id, code, kind, action, status, created, caller, fields FROM asks " +
                            "WHERE notified IS NULL AND (status = 'pending' OR kind = 'lead') ORDER BY created LIMIT 20");
    return { door_id: CFG.door_id, items: items.map((i) => ({ ask_id: i.ask_id, code: i.code, kind: i.kind, action: i.action,
             status: i.status, created: nowIso(i.created), caller: JSON.parse(i.caller), fields: JSON.parse(i.fields) })) };
  }

  async ownerAck(askIds, via) {
    const out = [];
    for (const id of (Array.isArray(askIds) ? askIds : []).slice(0, 20)) {
      const a = this.rows("SELECT * FROM asks WHERE ask_id = ? AND notified IS NULL", String(id))[0];
      if (!a) continue;
      this.sql.exec("UPDATE asks SET notified = ? WHERE ask_id = ?", Date.now() / 1000, a.ask_id);
      const who = JSON.parse(a.caller);
      out.push(DoorState.pub(this.receipt({ event: "owner_notified", ask_id: a.ask_id, ask_type: a.action,
        decision: a.kind === "lead" ? "allow" : "ask_owner", reason: "sent_to_owner", via: String(via || "").slice(0, 32),
        text_sha256: a.text_sha256, ...who })));
    }
    return { acked: out };
  }

  async ownerAnswer(code, yes, via) {
    const c = String(code || "").trim().toUpperCase();
    const a = this.rows("SELECT * FROM asks WHERE code = ? AND status = 'pending'", c)[0];
    if (!a) return { ok: false, error: "no open request with that code" };
    const now = Date.now() / 1000;
    this.sql.exec("UPDATE asks SET status = ?, answered = ? WHERE ask_id = ?", yes ? "approved" : "declined", now, a.ask_id);
    if (!yes) this.sql.exec("INSERT INTO declines (peer, action, norm, ts, ask_id) VALUES (?, ?, ?, ?, ?)", a.peer, a.action, normalize(a.body), now, a.ask_id);
    const who = JSON.parse(a.caller);
    const rec = this.receipt({ event: "owner_answer", ask_id: a.ask_id, ask_type: a.action, decision: yes ? "allow" : "deny",
      reason: yes ? "owner_approved" : "owner_declined", decided_by: "owner:" + CFG.owner, via: String(via || "").slice(0, 32),
      text_sha256: a.text_sha256, ...who });
    return { ok: true, ask_id: a.ask_id, answer: yes ? "yes" : "no", receipt: DoorState.pub(rec) };
  }

  async receipts(since, limit) {
    const rows = this.rows("SELECT record, hash FROM receipts WHERE seq > ? ORDER BY seq LIMIT ?",
                           Number(since) || 0, Math.min(Number(limit) || 200, 500));
    return rows.map((r) => ({ ...JSON.parse(r.record), hash: r.hash }));
  }

  async head() {
    const last = this.rows("SELECT seq, hash FROM receipts ORDER BY seq DESC LIMIT 1")[0];
    return { seq: last ? last.seq : 0, hash: last ? last.hash : GENESIS };
  }
}

// --- tools --------------------------------------------------------------------------------------
const READ = { readOnlyHint: true, idempotentHint: true, destructiveHint: false, openWorldHint: false };
const ACT = { readOnlyHint: false, idempotentHint: true, destructiveHint: false, openWorldHint: true };
const WHO = {
  caller_agent: { type: "string", maxLength: 64, description: "Your agent's name (self reported, recorded)." },
  caller_model: { type: "string", maxLength: 64, description: "The model you run on (self reported, recorded)." },
  acting_for: { type: "string", maxLength: 64, description: "The person you act for (name, recorded)." },
  contact_email: { type: "string", maxLength: 254, description: "Where the owner can reach that person." },
};
const WHO_REQ = ["caller_agent", "caller_model", "acting_for", "contact_email"];
const TOOLS = [
  { name: "door_rules", title: "Door rules",
    description: "The door's rules in plain English: what it does, what it always refuses.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false }, annotations: READ },
  { name: "list_facts", title: "List facts",
    description: "All facts from the business's public facts page, word for word, with the page hash.",
    inputSchema: { type: "object", properties: { caller_agent: { type: "string", maxLength: 64 } }, additionalProperties: false },
    annotations: READ },
  { name: "lookup_fact", title: "Look up a fact",
    description: "Find the one fact on the page that answers a question. Returns found=false rather than guess.",
    inputSchema: { type: "object", properties: { question: { type: "string", maxLength: 2000 },
      caller_agent: { type: "string", maxLength: 64 } }, required: ["question"], additionalProperties: false },
    annotations: READ },
  { name: "who_am_i", title: "Who am I to this door",
    description: "How the door sees this request: self reported (unsigned), or verified for a domain (Web Bot Auth signature).",
    inputSchema: { type: "object", properties: {}, additionalProperties: false }, annotations: READ },
  { name: "request_call", title: "Request a call",
    description: "Ask for a call with the founder for the person you act for. Becomes one yes/no question to the owner; " +
                 "collect the answer later with check_request. Never books, never charges.",
    inputSchema: { type: "object", properties: { ...WHO, name: { type: "string", maxLength: 64 },
      topic: { type: "string", enum: TOPICS }, preferred_window: { type: "string", enum: WINDOWS },
      note: { type: "string", maxLength: 2000, description: "Cut to 280 characters, links removed, read only by the owner." } },
      required: [...WHO_REQ, "topic"], additionalProperties: false }, annotations: ACT },
  { name: "ask_question", title: "Ask a question",
    description: "Answered from the facts page when the page clearly answers it; otherwise one yes/no question to the owner " +
                 "on whether he answers it by email.",
    inputSchema: { type: "object", properties: { ...WHO, question: { type: "string", maxLength: 2000 } },
      required: [...WHO_REQ, "question"], additionalProperties: false }, annotations: ACT },
  { name: "leave_lead", title: "Leave a lead",
    description: "Leave a short lead for the owner to read himself. Allowed without a question; counts toward the owner's daily limit.",
    inputSchema: { type: "object", properties: { ...WHO, topic: { type: "string", enum: TOPICS },
      note: { type: "string", maxLength: 2000 } }, required: [...WHO_REQ, "topic"], additionalProperties: false }, annotations: ACT },
  { name: "check_request", title: "Check a request",
    description: "Collect the owner's answer to a request you made. A yes is carried out once.",
    inputSchema: { type: "object", properties: { request_id: { type: "string", maxLength: 16 }, caller_agent: WHO.caller_agent },
      required: ["request_id", "caller_agent"], additionalProperties: false }, annotations: ACT },
];
const ACT_NAMES = new Set(["request_call", "ask_question", "leave_lead", "check_request"]);

function factById(id) { return BUNDLE.facts.find((f) => f.id === id) || null; }

function refuseRead(kind) {
  const ref = factById(BUNDLE.floor_reply[kind]);
  const out = { status: "refused", found: false, answer: null, refused: BUNDLE.floor_label[kind],
    message: "This door does not handle " + BUNDLE.floor_label[kind] + ". It never quotes or sets prices, moves money, " +
             "deletes data, shares client data, or makes commitments in the owner's name." };
  if (ref) { out.page_says = ref.answer; out.page_fact_id = ref.id; }
  return out;
}

function readTool(name, args) {
  if (name === "door_rules") {
    return { business: BUNDLE.business, rules: RULES, facts_source: BUNDLE.source, read_only: false,
             tools: TOOLS.map((t) => t.name), owner_questions_per_day: LIM.owner_messages_per_day };
  }
  if (name === "list_facts") {
    return { business: BUNDLE.business, source: BUNDLE.source, page_sha256: BUNDLE.page_sha256,
             summary: BUNDLE.summary, facts: BUNDLE.facts,
             note: "Every answer is the page's own text, word for word. Nothing here is generated." };
  }
  if (name === "lookup_fact") {
    const q = cleanNote(args && args.question);
    const kind = floorHit(q);
    if (kind) return refuseRead(kind);
    const hit = search(q);
    if (!hit) return { found: false, answer: null,
      note: "The facts page does not answer this. Use ask_question to put it to the owner, or see lookup_fact 'how do I book'." };
    return { found: true, fact_id: hit.id, question: hit.question, answer: hit.answer, links: hit.links,
             source: BUNDLE.source, match_score: hit.match_score };
  }
  return undefined;
}

// Names come from tool arguments (self reported). Identity comes only from the HTTP signature check,
// never from arguments, so typing a domain proves nothing.
function callerOf(a, ident) {
  const c = { caller_agent: label(a.caller_agent, "caller_agent"), caller_model: label(a.caller_model, "caller_model"),
              acting_for: label(a.acting_for, "acting_for"), identity: "self_reported", identity_label: "self reported" };
  c.principal = c.caller_agent;
  if (ident && ident.reason === "ok" && !ident.rejected) {
    if (ident.level === ID.SIGNED) Object.assign(c, { identity: "signed_no_domain", principal: "key:" + ident.keyid });
    if (ident.level === ID.DOMAIN_VERIFIED || ident.level === ID.PARTNER)
      Object.assign(c, { identity: ident.level, principal: ident.domain, verified_domain: ident.domain });
    Object.assign(c, { identity_label: ID.label(ident), signature_agent: ident.agent_url, keyid: ident.keyid,
                       request_sig_sha256: ident.signature_sha256 });
  }
  return c;
}

function whoAmI(ident) {
  const i = ident || { level: ID.UNSIGNED, reason: "no_signature" };
  const out = { identity: i.level, label: ID.label(i), reason: i.reason,
    how_to_verify: "Sign each request with Web Bot Auth (" + ID.STANDARD_URL + ") and publish your key at https://<your-domain>" +
                   ID.WELL_KNOWN_PATH + ". The owner then sees 'verified: <your-domain>'." };
  if (i.domain) out.verified_domain = i.domain;
  if (i.agent_url) out.signature_agent = i.agent_url;
  if (i.keyid) out.keyid = i.keyid;
  if (i.card && Object.keys(i.card).length) out.card_from_your_domain = i.card;
  return out;
}

function fieldsOf(action, a, c) {
  const contact = String(a.contact_email || "").trim();
  if (!EMAIL.test(contact)) throw new Refused("contact_email must be a plain email address");
  const topic = a.topic || "other";
  if (!TOPICS.includes(topic)) throw new Refused("topic must be one of: " + TOPICS.join(", "));
  const window = a.preferred_window || "any";
  if (!WINDOWS.includes(window)) throw new Refused("preferred_window must be one of: " + WINDOWS.join(", "));
  const name = label(a.name || c.acting_for, "name");
  const note = cleanNote(action === "ask_question" ? a.question : a.note);
  return { name, contact, topic, window, note };
}

async function actTool(name, args, env, ipKey, ident) {
  const stub = env.DOOR.get(env.DOOR.idFromName(CFG.door_id));
  if (name === "check_request") return await stub.check(args.request_id, label(args.caller_agent, "caller_agent"));
  const c = callerOf(args, ident);
  if (name === "ask_question") {
    const q = cleanNote(args.question);
    if (!q) throw new Refused("question is empty");
    if (!floorHit(q)) {
      const hit = search(q, LIM.page_answer_min_score);
      if (hit) return { status: "answered_from_page", found: true, fact_id: hit.id, question: hit.question, answer: hit.answer,
                        links: hit.links, source: BUNDLE.source, match_score: hit.match_score,
                        note: "The facts page answers this, so the owner was not asked." };
    }
  }
  return await stub.act(name, c, fieldsOf(name, args, c), ipKey);
}

// --- MCP over streamable HTTP (stateless, JSON responses) ----------------------------------------
const ok = (id, result) => ({ jsonrpc: "2.0", id, result });
const err = (id, code, message) => ({ jsonrpc: "2.0", id: id ?? null, error: { code, message } });

async function handle(msg, env, ipKey, ident) {
  if (!msg || typeof msg !== "object" || msg.jsonrpc !== "2.0" || typeof msg.method !== "string")
    return err(msg && msg.id, -32600, "Invalid Request");
  if (!("id" in msg)) return null; // notifications: accepted, nothing to say
  const { id, method } = msg;
  const params = msg.params || {};
  switch (method) {
    case "initialize": {
      const want = params.protocolVersion;
      return ok(id, {
        protocolVersion: PROTOCOLS.includes(want) ? want : PROTOCOLS[0],
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: "agent-front-door", title: BUNDLE.business + " front door for AI agents",
                      version: VERSION, websiteUrl: BUNDLE.source },
        instructions: RULES,
      });
    }
    case "ping": return ok(id, {});
    case "tools/list": return ok(id, { tools: TOOLS });
    case "tools/call": {
      const name = String(params.name || "");
      const args = params.arguments && typeof params.arguments === "object" ? params.arguments : {};
      let res;
      try {
        res = ACT_NAMES.has(name) ? await actTool(name, args, env, ipKey, ident)
            : name === "who_am_i" ? whoAmI(ident) : readTool(name, args);
      } catch (e) {
        if (e instanceof Refused) {
          const r = { status: "refused", message: e.message };
          return ok(id, { content: [{ type: "text", text: JSON.stringify(r) }], structuredContent: r, isError: true });
        }
        const r = { status: "error", message: "door error; nothing was recorded" };
        return ok(id, { content: [{ type: "text", text: JSON.stringify(r) }], structuredContent: r, isError: true });
      }
      if (res === undefined) return err(id, -32602, "Unknown tool: " + name.slice(0, 64));
      return ok(id, { content: [{ type: "text", text: JSON.stringify(res) }], structuredContent: res, isError: false });
    }
    case "resources/list": return ok(id, { resources: [] });
    case "prompts/list": return ok(id, { prompts: [] });
    default: return err(id, -32601, "Method not found");
  }
}

const HDRS = { "content-type": "application/json", "cache-control": "no-store", "x-content-type-options": "nosniff",
               "access-control-allow-origin": "*", "access-control-allow-headers": "content-type, accept, mcp-protocol-version, mcp-session-id, signature, signature-input, signature-agent, content-digest",
               "access-control-allow-methods": "POST, OPTIONS" };
const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: HDRS });

function ownerOk(request, env) {
  const want = String(env.OWNER_TOKEN_SHA256 || "").toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(want)) return false; // no secret set: the owner side stays closed
  const got = (request.headers.get("authorization") || "").replace(/^Bearer\s+/i, "");
  if (got.length < 32) return false;
  const a = Buffer.from(sha256(got), "utf8"), b = Buffer.from(want, "utf8");
  return a.length === b.length && timingSafeEqual(a, b);
}

async function owner(request, env, path) {
  if (!ownerOk(request, env)) return json({ error: "unauthorized" }, 401);
  const stub = env.DOOR.get(env.DOOR.idFromName(CFG.door_id));
  let body = {};
  if (request.method === "POST") {
    const t = await request.text();
    if (t.length > MAX_BODY) return json({ error: "too large" }, 413);
    try { body = t ? JSON.parse(t) : {}; } catch { return json({ error: "bad json" }, 400); }
  }
  if (path === "/owner/pull" && request.method === "POST") return json(await stub.ownerPull());
  if (path === "/owner/ack" && request.method === "POST") return json(await stub.ownerAck(body.ask_ids, body.via));
  if (path === "/owner/answer" && request.method === "POST") {
    const ans = String(body.answer || "").toLowerCase();
    if (!["yes", "no"].includes(ans)) return json({ error: "answer must be yes or no" }, 400);
    const r = await stub.ownerAnswer(body.code, ans === "yes", body.via);
    return json(r, r.ok ? 200 : 409);
  }
  if (path === "/owner/receipts" && request.method === "GET") {
    const u = new URL(request.url);
    return json({ receipts: await stub.receipts(u.searchParams.get("since"), u.searchParams.get("limit")) });
  }
  return json({ error: "not found" }, 404);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: HDRS });

    // Rate limits: per caller IP, plus a ceiling for the whole door in each location.
    const ip = request.headers.get("cf-connecting-ip") || "unknown";
    if (env.PER_IP && !(await env.PER_IP.limit({ key: ip })).success)
      return json(err(null, -32000, "rate limit reached; try in a minute"), 429);
    if (env.WHOLE_DOOR && !(await env.WHOLE_DOOR.limit({ key: "door" })).success)
      return json(err(null, -32000, "door is busy; try in a minute"), 429);

    if (url.pathname.startsWith("/owner/")) return owner(request, env, url.pathname);
    if (url.pathname === "/receipts/head" && request.method === "GET") {
      const stub = env.DOOR.get(env.DOOR.idFromName(CFG.door_id));
      return json({ door_id: CFG.door_id, ...(await stub.head()) });
    }
    if (url.pathname === "/" && request.method === "GET")
      return json({ name: "agent-front-door", business: BUNDLE.business, read_only: false, mcp: url.origin + "/mcp",
                    transport: "streamable-http", tools: TOOLS.map((t) => t.name), facts_source: BUNDLE.source,
                    page_sha256: BUNDLE.page_sha256, owner_questions_per_day: LIM.owner_messages_per_day,
                    receipts_head: url.origin + "/receipts/head" });
    if (url.pathname !== "/mcp") return json({ error: "not found" }, 404);
    if (request.method !== "POST") return new Response(null, { status: 405, headers: { ...HDRS, allow: "POST, OPTIONS" } });

    const len = Number(request.headers.get("content-length") || 0);
    if (len > MAX_BODY) return json(err(null, -32600, "request too large"), 413);
    const text = await request.text();
    if (text.length > MAX_BODY) return json(err(null, -32600, "request too large"), 413);
    let msg;
    try { msg = JSON.parse(text); } catch { return json(err(null, -32700, "Parse error"), 400); }
    if (Array.isArray(msg)) return json(err(null, -32600, "batches are not supported"), 400);
    const ipKey = sha256("afd-ip\0" + ip).slice(0, 16);

    // Who is calling: Web Bot Auth signature check. No signature = self reported (still welcome).
    // A signature that fails is refused outright, before any tool runs.
    let ident = null;
    if (IDC.enabled) {
      const stub = env.DOOR.get(env.DOOR.idFromName(CFG.door_id));
      const v = new ID.Verifier(url.host, { cache: DIR_CACHE, partners: IDC.partners || {}, revokedKeyids: IDC.revoked_keyids || [],
        revokedAgents: IDC.revoked_agents || [], maxLifetime: IDC.max_signature_lifetime_s || 300,
        cacheTtl: IDC.key_cache_s || 300, seenNonce: (a, n, until) => stub.nonce(a, n, until) });
      ident = await v.verify(request.method, url.pathname + url.search, request.headers, new TextEncoder().encode(text));
      if (ident.rejected) {
        const reason = String(ident.reason).split(":")[0];
        return new Response(JSON.stringify({ jsonrpc: "2.0", id: msg && msg.id !== undefined ? msg.id : null,
          error: { code: -32001, message: ID.refusalMessage(reason), data: { status: "refused", reason, standard: ID.STANDARD_URL } } }),
          { status: 401, headers: { ...HDRS, "accept-signature": ID.ACCEPT_SIGNATURE } });
      }
    }
    const out = await handle(msg, env, ipKey, ident);
    if (out === null) return new Response(null, { status: 202, headers: HDRS });
    return json(out);
  },
};
