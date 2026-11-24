// Who is this agent, and which owner stands behind it? Web Bot Auth on the hosted door.
//
// A port of agent_front_door/identity.py (same rules, same reason codes) to the Workers runtime:
// Web Bot Auth (IETF draft-ietf-webbotauth-httpsig-protocol) = HTTP Message Signatures (RFC 9421)
// with Ed25519, a Signature-Agent header naming the URL of the agent's key directory (a JWK Set),
// and keyid = the key's JWK SHA-256 thumbprint (RFC 7638 / RFC 8037). When the directory sits at
// https://<domain>/.well-known/http-message-signatures-directory, that domain's owner stands behind
// the key, the way DKIM ties mail to a domain.
//
// Stricter than the draft's minimum, on purpose: the signature must cover method, authority, path,
// the body (Content-Digest, RFC 9530) and Signature-Agent, carry created + expires (at most 5 minutes
// apart) and a nonce that is accepted once. Directories are cached at most 5 minutes so a removed key
// stops working quickly. Pure: fetch, clock and the nonce store are passed in, so it runs under Node
// for tests and inside the Worker for real.
//
// It proves which domain's owner stands behind a request. It does not prove that owner is honest and
// it grants nothing by itself; the door's consent rules and the owner decide.

export const WELL_KNOWN_PATH = "/.well-known/http-message-signatures-directory";
export const DIRECTORY_MEDIA_TYPE = "application/http-message-signatures-directory+json";
export const TAG = "web-bot-auth";
export const DIRECTORY_TAG = "http-message-signatures-directory"; // tag on the directory response's own signatures
const MAX_DIRECTORY_SIG_LIFETIME = 90 * 86400;                     // a static directory may be signed for up to 90 days
export const STANDARD_URL = "https://datatracker.ietf.org/doc/draft-ietf-webbotauth-httpsig-protocol/";
export const UNSIGNED = "unsigned", SIGNED = "signed", DOMAIN_VERIFIED = "domain_verified", PARTNER = "partner";
export const RANK = { unsigned: 0, signed: 1, domain_verified: 2, partner: 3 };

const enc = new TextEncoder();

// ---------------------------------------------------------------------------------------- base64
export function b64urlEncode(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
export function b64Decode(text) {
  let t = String(text).replace(/-/g, "+").replace(/_/g, "/");
  t += "=".repeat((4 - (t.length % 4)) % 4);
  const bin = atob(t);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function b64Std(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}
async function sha256(bytes) { return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)); }
const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

export async function jwkThumbprint(jwk) {
  if (jwk.kty !== "OKP") throw new Error("only OKP (Ed25519) keys are supported");
  const canon = JSON.stringify({ crv: jwk.crv, kty: "OKP", x: jwk.x }); // members in lexical order
  return b64urlEncode(await sha256(enc.encode(canon)));
}

async function importJwk(jwk) {
  if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || typeof jwk.x !== "string") throw new Error("not an Ed25519 JWK");
  if (b64Decode(jwk.x).length !== 32) throw new Error("bad Ed25519 public key length");
  return crypto.subtle.importKey("jwk", { kty: "OKP", crv: "Ed25519", x: jwk.x }, { name: "Ed25519" }, false, ["verify"]);
}

// ------------------------------------------------------------------ structured fields (RFC 9651)
export class SFError extends Error {}
export class Token { constructor(v) { this.v = v; } toString() { return this.v; } }
export class Bytes { constructor(b) { this.b = b; } }

class P {
  constructor(s) { this.s = s; this.i = 0; }
  ws() { while (this.i < this.s.length && (this.s[this.i] === " " || this.s[this.i] === "\t")) this.i++; }
  peek() { return this.i < this.s.length ? this.s[this.i] : ""; }
  key() {
    const start = this.i, c = this.peek();
    if (!(/[a-z*]/.test(c))) throw new SFError("bad key at " + this.i);
    while (this.i < this.s.length && /[a-z0-9_\-.*]/.test(this.s[this.i])) this.i++;
    return this.s.slice(start, this.i);
  }
  bare() {
    const c = this.peek();
    if (c === '"') {
      this.i++;
      let out = "";
      while (this.i < this.s.length) {
        const ch = this.s[this.i++];
        if (ch === "\\") {
          const nxt = this.s[this.i];
          if (nxt !== '"' && nxt !== "\\") throw new SFError("bad escape");
          out += nxt; this.i++;
        } else if (ch === '"') return out;
        else if (ch.charCodeAt(0) < 0x20 || ch.charCodeAt(0) > 0x7e) throw new SFError("bad string char");
        else out += ch;
      }
      throw new SFError("unterminated string");
    }
    if (c === ":") {
      const end = this.s.indexOf(":", this.i + 1);
      if (end < 0) throw new SFError("unterminated byte sequence");
      const body = this.s.slice(this.i + 1, end);
      if (!/^[A-Za-z0-9+/=]*$/.test(body)) throw new SFError("bad byte sequence");
      this.i = end + 1;
      try { return new Bytes(b64Decode(body)); } catch { throw new SFError("bad base64"); }
    }
    if (c === "?") {
      const v = this.s[this.i + 1];
      if (v !== "0" && v !== "1") throw new SFError("bad boolean");
      this.i += 2;
      return v === "1";
    }
    if (c === "-" || /[0-9]/.test(c)) {
      const m = /^-?[0-9]{1,15}(\.[0-9]{1,3})?/.exec(this.s.slice(this.i));
      if (!m) throw new SFError("bad number");
      this.i += m[0].length;
      return m[1] ? Number(m[0]) : parseInt(m[0], 10);
    }
    if (/[A-Za-z*]/.test(c)) {
      const m = /^[A-Za-z*][A-Za-z0-9:\/!#$%&'*+\-.^_`|~]*/.exec(this.s.slice(this.i));
      this.i += m[0].length;
      return new Token(m[0]);
    }
    throw new SFError("bad item at " + this.i);
  }
  params() {
    const out = [];
    while (this.peek() === ";") {
      this.i++; this.ws();
      const k = this.key();
      let v = true;
      if (this.peek() === "=") { this.i++; v = this.bare(); }
      out.push([k, v]);
    }
    return out;
  }
  itemOrInner() {
    if (this.peek() === "(") {
      this.i++;
      const items = [];
      for (;;) {
        this.ws();
        if (this.peek() === ")") { this.i++; break; }
        if (!this.peek()) throw new SFError("unterminated inner list");
        const v = this.bare();
        items.push([v, this.params()]);
        const n = this.peek();
        if (n !== " " && n !== ")") throw new SFError("bad inner list");
      }
      return [items, this.params()];
    }
    const v = this.bare();
    return [v, this.params()];
  }
  dictionary() {
    const out = new Map();
    this.ws();
    while (this.i < this.s.length) {
      const k = this.key();
      let mem;
      if (this.peek() === "=") { this.i++; mem = this.itemOrInner(); } else mem = [true, this.params()];
      out.set(k, mem);
      this.ws();
      if (this.i >= this.s.length) break;
      if (this.peek() !== ",") throw new SFError("expected comma");
      this.i++; this.ws();
      if (this.i >= this.s.length) throw new SFError("trailing comma");
    }
    return out;
  }
}
export function parseDictionary(value) { return new P(String(value || "")).dictionary(); }

function serBare(v) {
  if (v instanceof Token) return v.v;
  if (v instanceof Bytes) return ":" + b64Std(v.b) + ":";
  if (v === true) return "?1";
  if (v === false) return "?0";
  if (typeof v === "number") return String(v);
  if (typeof v === "string") {
    if (/[^\x20-\x7e]/.test(v)) throw new SFError("non-ascii string");
    return '"' + v.replace(/\\/g, "\\\\").replace(/"/g, '\\"') + '"';
  }
  throw new SFError("cannot serialize");
}
const serParams = (ps) => ps.map(([k, v]) => (v === true ? ";" + k : ";" + k + "=" + serBare(v))).join("");
function serItem(v, ps = []) {
  if (Array.isArray(v)) return "(" + v.map(([iv, ip]) => serBare(iv) + serParams(ip)).join(" ") + ")" + serParams(ps);
  return serBare(v) + serParams(ps);
}

// --------------------------------------------------------------------------- signature base
// msg = { method, authority, path, query, headers: {lowercase: value} }
function componentValue(msg, name, params) {
  if (name === "@method") return msg.method.toUpperCase();
  if (name === "@authority") return msg.authority.toLowerCase();
  if (name === "@path") return msg.path || "/";
  if (name === "@query") return "?" + (msg.query || "");
  if (name === "@target-uri") return "https://" + msg.authority.toLowerCase() + (msg.path || "/") + (msg.query ? "?" + msg.query : "");
  if (name.startsWith("@")) throw new SFError("unsupported derived component " + name);
  if (!(name in msg.headers)) throw new SFError("covered header " + name + " is missing");
  const rawIn = String(msg.headers[name]);
  const raw = rawIn.includes("\n") ? rawIn.split(/\s+/).filter(Boolean).join(" ") : rawIn.trim();
  const key = params.find(([k]) => k === "key");
  if (key) {
    const d = parseDictionary(raw);
    if (!d.has(key[1])) throw new SFError("dictionary member " + key[1] + " missing from " + name);
    const [v, vp] = d.get(key[1]);
    return serItem(v, vp);
  }
  return raw;
}

export function signatureBase(msg, comps, sigParams) {
  const lines = [], seen = new Set();
  for (const [name, params] of comps) {
    const ident = serItem(name, params);
    if (seen.has(ident)) throw new SFError("duplicate component");
    seen.add(ident);
    lines.push(ident + ": " + componentValue(msg, name, params));
  }
  const pv = serItem(comps.map(([n, p]) => [n, p]), sigParams);
  lines.push('"@signature-params": ' + pv);
  return enc.encode(lines.join("\n"));
}

export async function contentDigest(bodyBytes) { return "sha-256=:" + b64Std(await sha256(bodyBytes)) + ":"; }

// ------------------------------------------------------------------------------- url guards
export function normalizeAgentUrl(url) {
  try {
    const u = new URL(String(url).trim());
    const host = u.hostname.toLowerCase();
    const netloc = u.port && u.port !== "443" ? host + ":" + u.port : host;
    return u.protocol.toLowerCase() + "//" + netloc + (u.pathname || "/");
  } catch { return String(url); }
}

export function safeHttpsUrl(url) {
  let u;
  try { u = new URL(url); } catch { return "bad_url"; }
  if (u.protocol !== "https:") return "not_https";
  if (u.username || u.password) return "credentials_in_url";
  const host = u.hostname.toLowerCase();
  if (!host || !host.includes(".")) return "bad_host";
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.startsWith("[")) return "ip_literal_host";
  if (host === "localhost" || /\.(localhost|local|internal|lan|home\.arpa)$/.test(host)) return "local_host";
  if (u.port && u.port !== "443") return "non_default_port";
  if (u.hash) return "fragment_in_url";
  return null;
}

// --------------------------------------------------------------------------------- identity
export function label(ident) {
  if (ident.level === PARTNER) return "partner: " + ident.domain;
  if (ident.level === DOMAIN_VERIFIED) return "verified: " + ident.domain;
  if (ident.level === SIGNED) return "signed, no domain: " + ident.agent_url;
  return "self reported";
}
const unsigned = (reason = "no_signature") => ({ level: UNSIGNED, reason, rejected: false });
const rejected = (reason, extra = {}) => ({ level: UNSIGNED, reason, rejected: true, ...extra });

// Default directory fetch for the Worker: no redirects, short timeout, size cap.
export async function defaultFetch(url, maxBytes = 65536) {
  const r = await fetch(url, { redirect: "manual", signal: AbortSignal.timeout(3000),
    headers: { accept: DIRECTORY_MEDIA_TYPE + ", application/json", "user-agent": "agent-front-door/0.3 (+key directory check)" } });
  const buf = new Uint8Array(await r.arrayBuffer());
  return { status: r.status, cacheControl: r.headers.get("cache-control") || "", body: buf.length > maxBytes ? null : buf,
           signature: r.headers.get("signature") || "", signatureInput: r.headers.get("signature-input") || "" };
}

function maxAge(cc) {
  for (let part of String(cc || "").split(",")) {
    part = part.trim().toLowerCase();
    if (part.startsWith("max-age=")) { const n = parseInt(part.slice(8), 10); return Number.isFinite(n) ? n : null; }
    if (part === "no-store" || part === "no-cache") return 0;
  }
  return null;
}

export class Verifier {
  // opts: fetch(url) -> {status, cacheControl, body}; clock() -> seconds; seenNonce(agentUrl, nonce, until) -> Promise<bool fresh>
  constructor(authority, opts = {}) {
    this.authority = String(authority).toLowerCase();
    this.fetch = opts.fetch || defaultFetch;
    this.clock = opts.clock || (() => Date.now() / 1000);
    this.seenNonce = opts.seenNonce;
    this.maxSkew = opts.maxSkew ?? 60;
    this.maxLifetime = opts.maxLifetime ?? 300;
    this.cacheTtl = opts.cacheTtl ?? 300;
    this.negativeTtl = opts.negativeTtl ?? 60;
    this.partners = Object.fromEntries(Object.entries(opts.partners || {}).map(([d, s]) => [d.toLowerCase(), s]));
    this.revokedKeyids = new Set(opts.revokedKeyids || []);
    this.revokedAgents = new Set((opts.revokedAgents || []).map(normalizeAgentUrl));
    this.cache = opts.cache || new Map();
    // The draft: a verifier relying on the domain MUST check the directory response's own signatures.
    this.requireDirectorySignature = opts.requireDirectorySignature ?? true;
  }

  // Thumbprints of the directory's keys that signed this response for the directory's own host.
  async directorySignedKeys(host, res, keys, now) {
    const good = new Set();
    let inputs, sigs;
    try { inputs = parseDictionary(res.signatureInput || ""); sigs = parseDictionary(res.signature || ""); } catch { return good; }
    const msg = { method: "GET", authority: host, path: WELL_KNOWN_PATH, query: "", headers: {} };
    for (const [lbl, [comps, sp]] of inputs) {
      const p = Object.fromEntries(sp);
      if (!Array.isArray(comps) || p.tag !== DIRECTORY_TAG || !keys.has(p.keyid)) continue;
      if (!Number.isInteger(p.created) || !Number.isInteger(p.expires) || p.created > now + this.maxSkew ||
          p.expires < now - this.maxSkew || p.expires - p.created > MAX_DIRECTORY_SIG_LIFETIME) continue;
      if (!comps.some(([n]) => n === "@authority") || comps.some(([n]) => typeof n !== "string")) continue;
      const sig = (sigs.get(lbl) || [null])[0];
      if (!(sig instanceof Bytes)) continue;
      try {
        const base = signatureBase(msg, comps, sp);
        if (await crypto.subtle.verify({ name: "Ed25519" }, keys.get(p.keyid).key, sig.b, base)) good.add(p.keyid);
      } catch { /* not a valid signature */ }
    }
    return good;
  }

  async directory(url) {
    const now = this.clock();
    const hit = this.cache.get(url);
    if (hit && now - hit.fetched < hit.ttl) return hit.ok ? hit : null;
    let res;
    try { res = await this.fetch(url); } catch { res = { status: 0, body: null }; }
    const entry = await this.parseDirectory(res, now, new URL(url).host.toLowerCase());
    if (!entry) {
      if (hit && hit.ok && now - hit.fetched < hit.ttl + this.negativeTtl) return hit;
      this.cache.set(url, { keys: new Map(), card: {}, fetched: now, ttl: this.negativeTtl, ok: false });
      return null;
    }
    this.cache.set(url, entry);
    return entry;
  }

  async parseDirectory(res, now, host) {
    if (!res || res.status !== 200 || !res.body || !res.body.length) return null;
    let doc;
    try { doc = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(res.body)); } catch { return null; }
    if (!doc || typeof doc !== "object" || !Array.isArray(doc.keys)) return null;
    const keys = new Map();
    for (const jwk of doc.keys.slice(0, 32)) {
      if (!jwk || typeof jwk !== "object" || jwk.kty !== "OKP" || jwk.crv !== "Ed25519") continue;
      try { const k = await importJwk(jwk); keys.set(await jwkThumbprint(jwk), { jwk, key: k }); } catch { /* skip bad key */ }
    }
    if (this.requireDirectorySignature) {
      const signed = await this.directorySignedKeys(host, res, keys, now);
      for (const kid of [...keys.keys()]) if (!signed.has(kid)) keys.delete(kid);
    }
    const rawCard = doc.agent_card && typeof doc.agent_card === "object" ? doc.agent_card : {};
    const card = {};
    for (const k of ["client_name", "client_uri", "contacts", "acts_for"]) if (k in rawCard) card[k] = rawCard[k];
    const ma = maxAge(res.cacheControl);
    const ttl = ma === null ? this.cacheTtl : Math.max(0, Math.min(ma, this.cacheTtl));
    return { keys, card, fetched: now, ttl, ok: true };
  }

  // method, pathAndQuery, headers (Headers or plain object), bodyBytes (Uint8Array)
  async verify(method, pathAndQuery, headers, bodyBytes) {
    const h = {};
    if (typeof headers.forEach === "function" && !(headers instanceof Map)) headers.forEach((v, k) => { h[k.toLowerCase()] = v; });
    else for (const [k, v] of Object.entries(headers)) h[k.toLowerCase()] = v;
    if (!("signature" in h) && !("signature-input" in h)) return unsigned("no_signature");
    try { return await this._verify(method, pathAndQuery, h, bodyBytes || new Uint8Array()); }
    catch (e) {
      if (e instanceof SFError) return rejected("malformed_signature_headers: " + e.message);
      return rejected("verification_error");
    }
  }

  async _verify(method, pathAndQuery, h, body) {
    const now = Math.floor(this.clock());
    const inputs = parseDictionary(h["signature-input"] || "");
    const sigs = parseDictionary(h["signature"] || "");
    let lbl = null;
    for (const [k, [v, p]] of inputs) if (Array.isArray(v) && p.some(([pk, pv]) => pk === "tag" && pv === TAG)) { lbl = k; break; }
    if (lbl === null) return rejected("no_web_bot_auth_signature");
    const [compsRaw, sp] = inputs.get(lbl);
    const params = Object.fromEntries(sp);
    const sigVal = (sigs.get(lbl) || [null])[0];
    if (!(sigVal instanceof Bytes)) return rejected("signature_missing_for_label");
    const sigHash = hex(await sha256(sigVal.b));
    const comps = [];
    for (const [v, p] of compsRaw) {
      if (typeof v !== "string") return rejected("bad_component");
      comps.push([v, p]);
    }
    const has = (n, p = []) => comps.some(([cn, cp]) => cn === n && JSON.stringify(cp) === JSON.stringify(p));
    if (!has("@authority") && !has("@target-uri")) return rejected("authority_not_covered");
    if (!has("signature-agent", [["key", lbl]])) return rejected("signature_agent_not_covered");
    for (const need of ["@method", "@path"]) if (!has(need) && !has("@target-uri")) return rejected(need.slice(1) + "_not_covered");
    if (!has("content-digest")) return rejected("body_not_covered");
    const qi = pathAndQuery.indexOf("?");
    const path = qi < 0 ? pathAndQuery : pathAndQuery.slice(0, qi), query = qi < 0 ? "" : pathAndQuery.slice(qi + 1);
    if (query && !has("@query") && !has("@target-uri")) return rejected("query_not_covered");

    const { created, expires, nonce, keyid, alg } = params;
    if (!Number.isInteger(created) || !Number.isInteger(expires)) return rejected("created_and_expires_required");
    if (created > now + this.maxSkew) return rejected("created_in_future");
    if (expires < now - this.maxSkew) return rejected("expired");
    if (expires - created > this.maxLifetime || expires <= created) return rejected("lifetime_too_long");
    if (typeof nonce !== "string" || nonce.length < 16) return rejected("nonce_required");
    if (typeof keyid !== "string" || !keyid) return rejected("keyid_required");
    if (alg !== undefined && alg !== "ed25519") return rejected("unsupported_alg");

    const want = await sha256(body);
    let digestOk = (h["content-digest"] || "").trim() === "sha-256=:" + b64Std(want) + ":";
    if (!digestOk) {
      try {
        const d = parseDictionary(h["content-digest"] || "");
        const got = (d.get("sha-256") || [null])[0];
        digestOk = got instanceof Bytes && got.b.length === want.length && got.b.every((x, i) => x === want[i]);
      } catch { digestOk = false; }
    }
    if (!digestOk) return rejected("body_digest_mismatch");

    const agents = parseDictionary(h["signature-agent"] || "");
    const member = agents.get(lbl);
    if (!member || typeof member[0] !== "string" || member[1].length) return rejected("signature_agent_member_invalid");
    const agentUrl = normalizeAgentUrl(member[0]);
    const bad = safeHttpsUrl(agentUrl);
    if (bad) return rejected("signature_agent_url_refused: " + bad);
    const u = new URL(agentUrl);
    const domain = u.hostname.toLowerCase();
    const common = { agent_url: agentUrl, domain: "", keyid, created, expires, nonce, signature_sha256: sigHash };

    if (this.revokedAgents.has(agentUrl) || this.revokedKeyids.has(keyid)) return rejected("revoked_by_door", common);
    const d = await this.directory(agentUrl);
    if (!d) return { level: UNSIGNED, reason: "directory_unreachable", rejected: false, ...common };
    const entry = d.keys.get(keyid);
    if (!entry) return rejected("key_not_published_by_claimed_owner", common);
    const { nbf, exp } = entry.jwk;
    if (typeof nbf === "number" && now < nbf) return rejected("key_not_yet_valid", common);
    if (typeof exp === "number" && now >= exp) return rejected("key_expired", common);

    const msg = { method: method.toUpperCase(), authority: this.authority, path: path || "/", query, headers: h };
    let base;
    try { base = signatureBase(msg, comps, sp); } catch (e) { return rejected("cannot_build_signature_base: " + e.message, common); }
    const good = await crypto.subtle.verify({ name: "Ed25519" }, entry.key, sigVal.b, base);
    if (!good) return rejected("bad_signature", common);

    if (this.seenNonce && !(await this.seenNonce(agentUrl, nonce, expires + this.maxSkew))) return rejected("replayed", common);

    const wellKnown = u.pathname === WELL_KNOWN_PATH;
    let level = wellKnown ? DOMAIN_VERIFIED : SIGNED;
    if (level === DOMAIN_VERIFIED && this.partners[domain]) level = PARTNER;
    common.domain = wellKnown ? domain : "";
    return { level, reason: "ok", rejected: false, card: d.card, ...common };
  }
}

// What a 401 says, and the header that asks for a proper signature (draft: Accept-Signature).
export function refusalMessage(reason) {
  return "This request carried a Web Bot Auth signature that did not check out (" + reason + "), so nothing was done. " +
         "Send it unsigned (you are labeled self reported) or sign it correctly: RFC 9421 Ed25519 over @method, " +
         "@authority, @path, content-digest and signature-agent, with created, expires (5 minutes at most), a one-time " +
         "nonce and tag=\"web-bot-auth\", key published at https://<your-domain>" + WELL_KNOWN_PATH + ". Standard: " + STANDARD_URL;
}
export const ACCEPT_SIGNATURE = 'sig1=("@method" "@authority" "@path" "content-digest" "signature-agent";key="sig1");' +
  'tag="web-bot-auth";alg="ed25519"';
