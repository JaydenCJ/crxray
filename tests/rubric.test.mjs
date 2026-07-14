// The risk rubric: severity weights, category caps, level buckets, the
// worst-finding floor, and deterministic finding order.
import test from "node:test";
import assert from "node:assert/strict";

import { scoreFindings, sortFindings, levelRank, SEVERITY_WEIGHTS, CATEGORY_CAP } from "../dist/rubric.js";

function finding(severity, category = "network", rule = "TEST_RULE", file = "a.js") {
  return { rule, severity, category, title: "t", detail: "d", file };
}

test("no findings scores 0 and grades minimal", () => {
  assert.deepEqual(scoreFindings([]), { score: 0, level: "minimal", byCategory: {} });
});

test("severity weights add up within a category", () => {
  const { score, byCategory } = scoreFindings([
    finding("medium"),
    finding("low"),
    finding("low"),
  ]);
  assert.equal(score, SEVERITY_WEIGHTS.medium + 2 * SEVERITY_WEIGHTS.low);
  assert.equal(byCategory.network, score);
});

test("a category saturates at the cap — quantity cannot fake severity", () => {
  const many = Array.from({ length: 30 }, () => finding("medium"));
  const { score, byCategory } = scoreFindings(many);
  assert.equal(byCategory.network, CATEGORY_CAP);
  assert.equal(score, CATEGORY_CAP);
});

test("categories add across axes and the total caps at 100", () => {
  const findings = [
    ...Array.from({ length: 10 }, () => finding("critical", "permissions")),
    ...Array.from({ length: 10 }, () => finding("critical", "remote-code")),
    ...Array.from({ length: 10 }, () => finding("critical", "network")),
  ];
  const { score, level } = scoreFindings(findings);
  assert.equal(score, 100); // 3 × capped 45 = 135 → clamped
  assert.equal(level, "critical");
});

test("the worst finding floors the level: one critical is never 'minimal'", () => {
  const one = scoreFindings([finding("critical")]);
  assert.equal(one.score, SEVERITY_WEIGHTS.critical);
  assert.equal(one.level, "high"); // bucket says medium; floor lifts to high
  const oneHigh = scoreFindings([finding("high")]);
  assert.equal(oneHigh.level, "medium"); // bucket says low; floor lifts to medium
  const oneMedium = scoreFindings([finding("medium")]);
  assert.equal(oneMedium.level, "low"); // no floor below high severity
  // The ordering the floors (and --fail-on) rely on.
  const order = ["minimal", "low", "medium", "high", "critical"].map(levelRank);
  assert.deepEqual(order, [0, 1, 2, 3, 4]);
});

test("sortFindings is total and deterministic: severity, category, rule, file", () => {
  const input = [
    finding("medium", "network", "B_RULE", "b.js"),
    finding("critical", "remote-code", "A_RULE", "a.js"),
    finding("medium", "network", "B_RULE", "a.js"),
    finding("medium", "permissions", "Z_RULE", "a.js"),
    finding("medium", "network", "A_RULE", "z.js"),
  ];
  const sorted = sortFindings(input);
  assert.deepEqual(
    sorted.map((f) => `${f.severity}/${f.category}/${f.rule}/${f.file}`),
    [
      "critical/remote-code/A_RULE/a.js",
      "medium/permissions/Z_RULE/a.js",
      "medium/network/A_RULE/z.js",
      "medium/network/B_RULE/a.js",
      "medium/network/B_RULE/b.js",
    ],
  );
  // Input order must not leak through: reversing it yields the same output.
  const reversed = sortFindings([...input].reverse());
  assert.deepEqual(reversed, sorted);
});
