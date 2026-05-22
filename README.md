# ssrfmap

Blind SSRF detection tool with Interactsh out-of-band (OAST) callback correlation.

## How OAST Correlation Works

Blind SSRF leaves no trace in the response — the only signal is the server making an outbound request to a host you control. ssrfmap uses the Interactsh protocol for this:

1. Generate an RSA-2048 keypair, register the public key + secret + 20-char correlation-id with the server
1. Registered host = `{correlation_id}{13 random}.oast.fun`
1. Each payload prepends a **unique token label** (`{token}.{host}`) so every callback is individually attributable
1. Poll `/poll` — the server returns one RSA-OAEP-encrypted AES key for the batch, plus per-interaction blobs (`16-byte IV ‖ AES-256-CFB ciphertext`)
1. Decrypt the batch key with the private RSA key, CFB-decrypt each blob, match the token back to the payload

### DNS vs HTTP callback

|Callback        |Meaning                                  |Verdict      |
|----------------|-----------------------------------------|-------------|
|HTTP interaction|Server actually made the request         |**CONFIRMED**|
|DNS interaction |Host was resolved but no request followed|**PARTIAL**  |
|None            |No callback received                     |NONE         |

## Install

```bash
pip install httpx cryptography
```

## Usage

```bash
python3 ssrfmap.py --url "https://target.com/api?fetch=x" --param fetch \
  --headers "Cookie: session=abc123" \
  --wait 15
```

## Payload Set

|Detection         |Techniques                                                                      |
|------------------|--------------------------------------------------------------------------------|
|**OAST-trackable**|Direct callback, Gopher, Dict, Parser confusion (`@`/`#`), Redirect→IMDS        |
|**Response-only** |Decimal/Octal/Hex IP, IPv6 `[::1]`, localhost, `0.0.0.0`, AWS IMDS, GCP metadata|

Response-only payloads target internal IPs that never reach your collaborator — they’re detected via metadata leakage in the response body, not via callback. The `Detect` column in the output table shows which is which.

## Output

- Matrix: Technique / Detect type / Token / Callback / Verdict
- Metadata leak flag (AWS keys, instance identity, GCP metadata in response body)
- Full decrypted interaction logs + per-payload history in JSON

## Notes

- Default collaborator is `oast.fun`; use `--collaborator` for self-hosted interactsh
- `--wait` controls how long to wait before polling (default 10s); increase for slow async backends
- `follow_redirects=False` so the Redirect→IMDS chain is tested server-side, not client-side
- For GCP metadata, the real endpoint requires a `Metadata-Flavor: Google` header server-side — flagged but may need a header-injection SSRF to fully exploit

## Author

[zwanski](https://zwanski.bio) — Zwanski Tech / Tinosoft Informatique
