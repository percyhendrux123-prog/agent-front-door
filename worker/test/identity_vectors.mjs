// Checks worker/src/identity.js (the Worker's Web Bot Auth verifier) against:
//   1. RFC 9421 B.2.6 (Ed25519) and the Web Bot Auth draft's E.2.1 test vector, byte for byte;
//   2. requests signed by the Python reference (identity_vectors.json, made by make_identity_vectors.py):
//      the port must give the same level and reason for each;
//   3. replay: the same signed request accepted once, refused the second time.
// Run: node worker/test/identity_vectors.mjs   (Node 20+; no network, no dependencies)
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import * as idm from "../src/identity.js";

let pass = 0, fail = 0;
const check = (name, cond, detail = "") => {
  if (cond) { pass++; console.log("PASS", name); } else { fail++; console.log("FAIL", name, detail); }
};
const RFC_KEY = { kty: "OKP", crv: "Ed25519", x: "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs" };
const b64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const imp = (jwk) => crypto.subtle.importKey("jwk", jwk, { name: "Ed25519" }, false, ["verify"]);

check("jwk thumbprint = draft value", (await idm.jwkThumbprint(RFC_KEY)) === "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U");

{
  const msg = { method: "POST", authority: "example.com", path: "/foo", query: "param=Value&Pet=dog",
    headers: { date: "Tue, 20 Apr 2021 02:07:55 GMT", "content-type": "application/json", "content-length": "18" } };
  const [comps, params] = idm.parseDictionary('sig-b26=("date" "@method" "@path" "@authority" "content-type" ' +
    '"content-length");created=1618884473;keyid="test-key-ed25519"').get("sig-b26");
  const base = idm.signatureBase(msg, comps, params);
  const sig = b64("wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==");
  check("RFC 9421 B.2.6 Ed25519 vector", await crypto.subtle.verify({ name: "Ed25519" }, await imp(RFC_KEY), sig, base));
}
{
  const msg = { method: "GET", authority: "example.com", path: "/", query: "",
    headers: { "signature-agent": 'sig2="https://signature-agent.test"' } };
  const [comps, params] = idm.parseDictionary('sig2=("@authority" "signature-agent";key="sig2");created=1735689600;' +
    'keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=4889289600;' +
    'nonce="n9p433xm+NJ3ph3upfBIGmsuwHw387YV7Q/F+6BSpGCVjYCqQw6rznNA8PVVLySrAWsv0hQtFioQb6E1YsauiA==";' +
    'tag="web-bot-auth"').get("sig2");
  const base = idm.signatureBase(msg, comps, params);
  const sig = b64("CGokAoY/FrPpyuzTe1Fb2kLTAH9Idw6qSFd1+D77r1firsMRCxeuLu5e6O+ek3zQgDMAzjiXtLVfqE00xnABCQ==");
  check("Web Bot Auth draft E.2.1 vector", await crypto.subtle.verify({ name: "Ed25519" }, await imp(RFC_KEY), sig, base));
}

const V = JSON.parse(readFileSync(fileURLToPath(new URL("./identity_vectors.json", import.meta.url)), "utf8"));
const enc = new TextEncoder();
const fakeFetch = async (url) => (V.directories[url]
  ? { status: 200, cacheControl: "", body: enc.encode(JSON.stringify(V.directories[url])),
      signature: (V.directory_headers[url] || {}).signature || "", signatureInput: (V.directory_headers[url] || {})["signature-input"] || "" }
  : { status: 404, cacheControl: "", body: null });
const mk = (seen) => new idm.Verifier(V.door, { fetch: fakeFetch, clock: () => V.now,
  seenNonce: async (a, n) => { const k = a + "|" + n; if (seen.has(k)) return false; seen.add(k); return true; } });

for (const c of V.cases) {
  const got = await mk(new Set()).verify("POST", c.path, c.headers, enc.encode(c.body));
  const reason = String(got.reason).split(":")[0];
  check("same as Python: " + c.name, got.level === c.level && reason === c.reason && !!got.rejected === c.rejected &&
        (got.domain || "") === (c.domain || "") && idm.label(got) === c.label,
        JSON.stringify({ got: [got.level, reason, got.rejected, idm.label(got)], want: [c.level, c.reason, c.rejected, c.label] }));
}

{
  const c = V.cases.find((x) => x.name === "verified");
  const v = mk(new Set());
  const a = await v.verify("POST", c.path, c.headers, enc.encode(c.body));
  const b = await v.verify("POST", c.path, c.headers, enc.encode(c.body));
  check("replay refused", a.reason === "ok" && b.rejected && b.reason === "replayed", JSON.stringify([a.reason, b.reason]));
  check("verified label", idm.label(a) === "verified: carol-agent.example");
  check("unsigned label", idm.label(await v.verify("POST", "/mcp", { "content-type": "application/json" }, enc.encode("{}"))) === "self reported");
  const p = new idm.Verifier(V.door, { fetch: fakeFetch, clock: () => V.now, partners: { "carol-agent.example": "carol" } });
  check("partner label", idm.label(await p.verify("POST", c.path, c.headers, enc.encode(c.body))) === "partner: carol-agent.example");
  const r = new idm.Verifier(V.door, { fetch: fakeFetch, clock: () => V.now, revokedKeyids: [a.keyid] });
  check("revoked by door", (await r.verify("POST", c.path, c.headers, enc.encode(c.body))).reason === "revoked_by_door");
}

{
  // a directory copied, headers and all, onto another host: its signatures cover @authority, so no credit
  const carolUrl = "https://carol-agent.example/.well-known/http-message-signatures-directory";
  const mirror = async (url) => fakeFetch(url.replace("mallory.example", "carol-agent.example"));
  const v = new idm.Verifier(V.door, { fetch: mirror, clock: () => V.now });
  const d = await v.directory("https://mallory.example/.well-known/http-message-signatures-directory");
  const real = await new idm.Verifier(V.door, { fetch: fakeFetch, clock: () => V.now }).directory(carolUrl);
  check("mirrored directory gives no keys", d && d.keys.size === 0 && real.keys.size === 1, JSON.stringify([d && d.keys.size, real.keys.size]));
  const late = await new idm.Verifier(V.door, { fetch: fakeFetch, clock: () => V.now + 31 * 86400 }).directory(carolUrl);
  check("expired directory signature gives no keys", late && late.keys.size === 0);
}

console.log(fail ? `FAILED ${fail} of ${pass + fail}` : `ALL PASS (${pass})`);
process.exit(fail ? 1 : 0);
