"""Make the files a domain publishes so doors can verify its agents (Web Bot Auth).

    uv run python tools/key_directory.py --key-file PATH --domain example.com --out DIR [--days 30]

Writes, from the private key file (which this script only reads, never prints or copies):
  DIR/http-message-signatures-directory   the JWK Set (public key only)
  DIR/directory-headers.json              Content-Type, CORS, Cache-Control, and the response's own
                                          Signature / Signature-Input (tag http-message-signatures-directory,
                                          over "@authority";req), valid for --days. Re-run and redeploy before then.
Serve the first at https://<domain>/.well-known/http-message-signatures-directory with the headers from the
second. A static host (Netlify, Pages) can serve them as fixed headers.

    uv run python tools/key_directory.py --new-key PATH     create a key file (mode 600); prints the keyid only
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from agent_front_door import identity as idm  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--key-file")
    ap.add_argument("--domain")
    ap.add_argument("--out")
    ap.add_argument("--days", type=int, default=30)
    ap.add_argument("--name", default="", help="client_name for the optional agent card")
    ap.add_argument("--uri", default="", help="client_uri for the optional agent card")
    ap.add_argument("--contact", default="", help="contact (mailto:...) for the optional agent card")
    ap.add_argument("--new-key")
    a = ap.parse_args()
    if a.new_key:
        p = Path(a.new_key).expanduser()
        if p.exists():
            sys.exit("refusing to overwrite " + str(p))
        k = idm.AgentKey.generate()
        k.to_file(p)
        print("keyid", k.keyid)
        return
    if not (a.key_file and a.domain and a.out):
        ap.error("--key-file, --domain and --out are required")
    key = idm.AgentKey.from_file(Path(a.key_file).expanduser())
    card = {k: v for k, v in (("client_name", a.name), ("client_uri", a.uri),
                              ("contacts", [a.contact] if a.contact else None)) if v}
    doc = idm.directory([key], card or None)
    for jwk in doc["keys"]:
        jwk.pop("alg", None)   # JOSE has no "ed25519" alg value; the draft's examples carry kty/crv/x/kid/use only
    now = int(time.time())
    sig = idm.sign_directory_response([key], a.domain, now=now, ttl=a.days * 86400)
    headers = {"Content-Type": idm.DIRECTORY_MEDIA_TYPE, "Access-Control-Allow-Origin": "*",
               "Cache-Control": "public, max-age=300", **sig}
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "http-message-signatures-directory").write_text(json.dumps(doc, indent=1) + "\n")
    (out / "directory-headers.json").write_text(json.dumps(headers, indent=1) + "\n")
    print("keyid", key.keyid)
    print("directory signature valid until", time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(now + a.days * 86400)))


if __name__ == "__main__":
    main()
