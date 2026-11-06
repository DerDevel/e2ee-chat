# Security Policy

## Supported Versions

Only the latest `main` branch receives security fixes.

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, use [GitHub private vulnerability reporting](../../security/advisories/new)
for this repository. If that is not available to you, open a regular issue
titled "Security contact" with a way to reach you — no vulnerability details —
and we will coordinate a private channel.

Please include:

- a description of the issue and its impact;
- exact commit hash you tested against;
- reproduction steps or a proof of concept;
- any mitigations you have in mind.

You can expect an acknowledgement within 72 hours. We will keep you informed
about the progress towards a fix and coordinate public disclosure with you.

## Scope

The security model of this project is documented in the
[README (Безопасность)](README.md#-безопасность). In particular:

- the relay server is **untrusted** for message content — it must never be able
  to decrypt traffic, forge a session that passes the SAS comparison, or
  desynchronize the two honest peers invisibly;
- attacks that require the user to ignore a **mismatching** safety code are out
  of scope: the SAS is the documented MITM detector and users are instructed to
  compare it fully;
- weak room keywords are a documented user responsibility; making enumeration
  *cheaper than the shipped rate limits allow* is in scope, the possibility of
  enumeration itself is not.

## Cryptographic notes

- Hybrid key agreement: X25519 + ML-KEM-768, transcript-bound via HKDF-SHA256.
- AEAD: ChaCha20-Poly1305 with per-direction keys and strictly monotonic
  counters.
- Transport: TLS 1.3 only, post-quantum X25519MLKEM768 key exchange preferred.

Changes to cryptographic primitives are treated as security-relevant and go
through adversarial review before merging.
