# Security policy

## Reporting a vulnerability

Please report security problems privately, through GitHub's **Report a vulnerability** button on the repository's Security tab, or by email to **chandu@portalvii.com**. Include the version (`psion --version`), what you found and how to reproduce it. Do not open a public issue for a vulnerability.

We reply within 3 business days, keep you informed while we fix the problem, and credit you in the release notes unless you prefer otherwise. Please give us 90 days, or until a fix is released, before disclosing publicly.

## Supported versions

Security fixes go into the latest release. Files written by any 1.x release stay readable by every later 1.x release; the committed test vectors in `crates/psionium-core/tests/vectors` enforce this.

## Scope

In scope: the `.psen` v2 format and its implementation in `psionium-core`, the `psion` command line, and `psionium-scan`. Especially interesting: anything that decrypts or verifies a file it should not, recovers plaintext or keys without the right identity, bypasses a required signer, crashes on crafted input, or leaks secret material into reports or logs.

Out of scope: attacks that need control of the user's machine or unlocked identity files, and weaknesses in the underlying AWS-LC primitives (report those to AWS-LC).

## Status

pSIONIUM uses only standardized algorithms, implemented by AWS-LC (and RustCrypto's `argon2` for passphrases), but its format and code have **not yet had an independent cryptographic review**. Until that review is published, do not rely on pSIONIUM alone for data you cannot afford to lose or expose. See `docs/threat-model.md` for what it protects against and what it does not.
