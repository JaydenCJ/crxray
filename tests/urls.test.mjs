// Endpoint extraction and classification: URL literal harvesting,
// deduplication across files, the tracker table's suffix matching, and
// the finding severities per endpoint kind.
import test from "node:test";
import assert from "node:assert/strict";

import { extractUrls, splitUrl, collectEndpoints, endpointFindings } from "../dist/urls.js";
import { lookupTracker } from "../dist/trackers.js";

test("extractUrls harvests http/https/ws/wss and trims trailing punctuation", () => {
  const text = `
    fetch("https://api.example.net/v1/data");
    const s = new WebSocket("wss://push.example.net/feed");
    // see https://example.net/docs/page.
    <a href="http://example.net/plain">x</a>
  `;
  const urls = extractUrls(text);
  assert.deepEqual(urls, [
    "https://api.example.net/v1/data",
    "wss://push.example.net/feed",
    "https://example.net/docs/page",
    "http://example.net/plain",
  ]);
});

test("splitUrl lowercases the host and strips ports and credentials", () => {
  assert.deepEqual(splitUrl("https://API.Example.NET:8443/x?y#z"), {
    scheme: "https",
    host: "api.example.net",
  });
  assert.deepEqual(splitUrl("http://user:pass@evil.example.net/x").host, "evil.example.net");
  assert.equal(splitUrl("not a url"), null);
});

test("tracker table matches by domain suffix, never by substring", () => {
  assert.equal(lookupTracker("google-analytics.com"), "analytics");
  assert.equal(lookupTracker("www.google-analytics.com"), "analytics");
  assert.equal(lookupTracker("region1.google-analytics.com"), "analytics");
  // Substring lookalikes must not match — that would smear innocents.
  assert.equal(lookupTracker("evilgoogle-analytics.com"), null);
  assert.equal(lookupTracker("api.example.net"), null);
  assert.equal(lookupTracker("hotjar.com"), "session-replay");
  assert.equal(lookupTracker("o450123.ingest.sentry.io"), "error-tracking");
});

test("each endpoint gets exactly one kind, by precedence", () => {
  const eps = collectEndpoints([
    {
      file: "bg.js",
      urls: [
        "https://www.googletagmanager.com/gtag/js",
        "http://198.51.100.23:8080/beacon",
        "https://xn--80ak6aa92e.example-shop.net/pay",
        "ws://relay.example.net/live",
        "http://plain.example.net/page",
        "http://127.0.0.1:8080/dev",
        "https://api.example.net/v1",
      ],
    },
  ]);
  const kinds = Object.fromEntries(eps.map((e) => [e.host, e.kind]));
  assert.equal(kinds["www.googletagmanager.com"], "tracker");
  assert.equal(kinds["198.51.100.23"], "raw-ip");
  assert.equal(kinds["xn--80ak6aa92e.example-shop.net"], "punycode");
  assert.equal(kinds["relay.example.net"], "insecure-ws");
  assert.equal(kinds["plain.example.net"], "insecure-http");
  assert.equal(kinds["127.0.0.1"], "loopback");
  assert.equal(kinds["api.example.net"], "plain");
});

test("collectEndpoints dedupes by URL, tracks files, sorts deterministically", () => {
  const eps = collectEndpoints([
    { file: "a.js", urls: ["https://api.example.net/v1", "https://api.example.net/v1"] },
    { file: "b.js", urls: ["https://api.example.net/v1"] },
  ]);
  assert.equal(eps.length, 1);
  assert.deepEqual(eps[0].files, ["a.js", "b.js"]);
  // Output order is by URL, independent of discovery order.
  const shuffled = collectEndpoints([
    {
      file: "a.js",
      urls: ["https://z.example.net/x", "https://a.example.net/x", "https://m.example.net/x"],
    },
  ]);
  assert.deepEqual(
    shuffled.map((e) => e.host),
    ["a.example.net", "m.example.net", "z.example.net"],
  );
});

test("findings: one per distinct host, not one per URL", () => {
  const findings = endpointFindings(
    collectEndpoints([
      {
        file: "bg.js",
        urls: [
          "https://www.google-analytics.com/collect",
          "https://www.google-analytics.com/g/collect",
          "https://www.google-analytics.com/mp/collect",
        ],
      },
    ]),
  );
  assert.equal(findings.filter((f) => f.rule === "NET_TRACKER").length, 1);
});

test("severities: session-replay high, analytics medium, raw IP high, plain http low", () => {
  const findings = endpointFindings(
    collectEndpoints([
      {
        file: "bg.js",
        urls: [
          "https://script.hotjar.com/rec.js",
          "https://www.google-analytics.com/collect",
          "https://203.0.113.9/c2",
          "http://legacy.example.net/api",
        ],
      },
    ]),
  );
  const byRule = Object.fromEntries(findings.map((f) => [`${f.rule}:${f.title}`, f.severity]));
  assert.equal(byRule["NET_TRACKER:session-replay endpoint: script.hotjar.com"], "high");
  assert.equal(byRule["NET_TRACKER:analytics endpoint: www.google-analytics.com"], "medium");
  assert.equal(byRule["NET_RAW_IP:hardcoded IP endpoint: 203.0.113.9"], "high");
  assert.equal(byRule["NET_INSECURE_HTTP:plaintext http endpoint: legacy.example.net"], "low");
  // Loopback and ordinary https endpoints never become findings.
  const quiet = endpointFindings(
    collectEndpoints([
      { file: "a.js", urls: ["http://127.0.0.1:3000/dev", "https://api.example.net/v1"] },
    ]),
  );
  assert.deepEqual(quiet, []);
});
