# Changelog

All notable changes to this project are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-07-12

### Added

- Container reader for CRX2, CRX3, bare ZIP and XPI, plus unpacked
  directories on disk. The dependency-free ZIP engine parses the central
  directory (tolerating stripped-prefix offsets and trailing comments),
  decompresses stored and deflated entries, and verifies CRC-32 so a
  payload tampered after packing is surfaced instead of trusted.
- CRX identity forensics: CRX2 public-key hashing and a minimal protobuf
  walker for the CRX3 header derive the a–p extension id, count RSA/ECDSA
  signature proofs (reported, never verified), and cross-check the
  manifest `key` against the container id.
- Tolerant `manifest.json` parsing (comments, trailing commas and BOM
  stripped, and recorded as weak evidence) with MV2/MV3 and
  Chrome/Firefox normalization into one summary.
- A permission rubric grading every API and host permission by
  worst-case capability, discounting optional grants, and escalating the
  combinations that amount to traffic interception or session theft
  (`cookies` + broad hosts, `webRequest` + blocking + broad hosts, an
  all-sites content script).
- Static scanners for remote-code loading (`eval`, `new Function`, string
  timers, remote `importScripts`/`import()`, `executeScript` code
  strings, remote `<script src>` in pages), CSP weakenings (`unsafe-eval`,
  whitelisted script origins), obfuscation (Shannon entropy, hex
  identifiers, packer signatures, escape density — separating minified
  from obfuscated), and privacy vectors (keystroke listeners, clipboard
  reads, bulk cookie harvesting). Comment-aware, no parser dependency.
- Endpoint extraction and classification against a built-in table of
  analytics, session-replay, ad and error-tracking networks, plus
  hardcoded raw-IP endpoints, punycode homographs and plaintext
  transports.
- Archive hygiene findings: zip-slip entry paths, duplicate entries, CRC
  mismatches, native executables (PE/ELF/Mach-O by magic) and shipped key
  material.
- A transparent risk rubric: fixed severity weights, per-category caps, a
  0–100 score, bucketed levels and a worst-finding floor, all documented
  in `docs/rubric.md` and fully deterministic.
- CLI with `scan` (default), `unpack` (zip-slip–safe extraction),
  `manifest`, `urls` and `id` subcommands; `--json` machine output,
  `--fail-on` exit-code gate for CI, and script-friendly exit codes
  (0 ok / 1 risk at/above the gate / 2 usage or input error).
- Public programmatic API (`openArchive`, `scanPackage`, `parseContainer`,
  `parseManifest`, `assessPermissions`, `scanCode`, `collectEndpoints`,
  `scoreFindings`, …) with type declarations.
- Test suite: 90 node:test tests (unit + CLI integration in fresh temp
  dirs, over byte-built ZIP/CRX fixtures) and an end-to-end
  `scripts/smoke.sh` against the bundled example extensions.

[0.1.0]: https://github.com/JaydenCJ/crxray/releases/tag/v0.1.0
