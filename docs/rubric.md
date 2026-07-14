# The crxray risk rubric

This document specifies exactly how crxray turns findings into a score and
a level. It is the contract behind the numbers: deterministic, explainable,
and stable across releases (a change here is a semver-visible change).

## Philosophy

The rubric grades **capability, not intent**. A permission is scored by
what it *enables* an attacker to do if the extension is compromised — via a
malicious update, a hijacked developer account, or a bought-out author —
not by the benign purpose the listing claims. This is deliberate: extension
supply-chain attacks almost always reuse permissions the extension already
holds. "It needs cookies for single sign-on" and "it can now read every
session token you have" are the same grant.

Findings are evidence, not verdicts. crxray never says "this extension is
malware"; it says "here is what this package *can* do, and here is the code
that surprised us." A human makes the call.

## Severities and weights

Every finding carries one severity. Severities map to fixed point weights:

| Severity | Weight | Meaning |
|---|---|---|
| `critical` | 30 | full compromise primitive (all-traffic interception, remote code, native binary) |
| `high` | 12 | serious capability or strong tampering signal |
| `medium` | 5 | notable capability or a soft signal worth a look |
| `low` | 2 | minor or context-dependent |
| `info` | 0 | recorded for transparency; contributes nothing to the score |

## Categories and the cap

Each finding belongs to one category. A category's contribution is the sum
of its findings' weights, **capped at 45 points**. The cap is the anti-noise
rule: forty tracker endpoints (medium, 5 each) still contribute only 45, so
sheer quantity in one axis can never outweigh a genuine remote-code hole in
another. The eight categories:

| Category | What it covers |
|---|---|
| `identity` | manifest presence/consistency, self-hosted updates, key/id mismatch |
| `permissions` | API and host permissions, and the combinations that escalate |
| `csp` | Content-Security-Policy weakenings (eval, remote script origins) |
| `remote-code` | eval, `new Function`, `importScripts`, dynamic `import()`, remote `<script>` |
| `obfuscation` | obfuscated or opaque high-entropy JavaScript |
| `network` | classified endpoints: trackers, raw IPs, punycode, plaintext |
| `privacy` | keystroke capture, clipboard reads, bulk cookie harvesting |
| `files` | archive hygiene: zip-slip, duplicates, CRC lies, native binaries |

## Obfuscation thresholds

The obfuscation detector is the one place the rubric uses numeric
thresholds, so they are part of this contract too. `OBF_OBFUSCATED`
(high) fires when any signal trips: the `eval(function(p,a,c,k,e,…)`
packer wrapper; five or more hex-pattern identifiers (`_0x…`); `\x`/`\u`
escape sequences above 4% of source in files over 200 bytes; or string
literals at over 5.0 bits/char of Shannon entropy across at least 256
chars feeding a visible decoder (`atob` / `String.fromCharCode`).
`OBF_OPAQUE_PAYLOAD` (medium) fires at over 5.5 bits/char across at
least 1024 chars with no visible decoder. `OBF_MINIFIED` (info) fires at
an average line length above 250 bytes. Changing any of these numbers is
a reviewed, semver-visible change.

## Score and level

The **score** is the sum of the (capped) category subtotals, clamped to
`0..100`. The **level** is bucketed from the score:

| Score | Level |
|---|---|
| 0–4 | `minimal` |
| 5–19 | `low` |
| 20–44 | `medium` |
| 45–69 | `high` |
| 70–100 | `critical` |

Then a **worst-finding floor** applies: a single `critical` finding floors
the level at `high`, and a single `high` finding floors it at `medium`. So
one remote-code loader in an otherwise quiet extension can never be reported
as `minimal` — the bucket might say so, the floor overrules it. The floor
only ever raises a level, never lowers it.

## `--fail-on`

`crxray scan --fail-on <level>` sets the exit-code gate for CI. The default
is `high`: the scan exits `1` when the risk level is `high` or `critical`,
`0` otherwise. `--fail-on never` always exits `0` (report-only). The order
for comparison is `minimal < low < medium < high < critical`.

## Determinism

Given the same input bytes and the same crxray version, the score, the
level, and the exact ordering of findings are byte-for-byte reproducible.
Findings are sorted by severity (worst first), then category, then rule id,
then file — no clocks, no hash-map iteration order, no locale collation.
This is what makes `--json` output safe to diff in review.
