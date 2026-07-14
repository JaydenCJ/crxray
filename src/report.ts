/**
 * Text rendering for the CLI. Everything here formats data computed by
 * scan.ts; nothing decides. Output is plain ASCII tables — greppable,
 * diffable, and stable across runs (the JSON view is the same data via
 * JSON.stringify).
 */
import type { ScanResult } from "./scan.js";
import type { ManifestSummary } from "./manifest.js";
import { VERSION } from "./version.js";

/** Render rows as an aligned two-space-separated table. */
export function table(rows: string[][], indent = "  "): string {
  if (rows.length === 0) return "";
  const widths: number[] = [];
  for (const row of rows) {
    row.forEach((cell, i) => {
      widths[i] = Math.max(widths[i] ?? 0, cell.length);
    });
  }
  return rows
    .map(
      (row) =>
        indent +
        row
          .map((cell, i) => (i === row.length - 1 ? cell : cell.padEnd(widths[i] as number)))
          .join("  ")
          .trimEnd(),
    )
    .join("\n");
}

function formatBytes(n: number | undefined): string {
  if (n === undefined) return "";
  if (n < 1024) return `${n} B`;
  return `${(n / 1024).toFixed(1)} KiB`;
}

function truncate(text: string, max: number): string {
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

function packageLine(r: ScanResult): string {
  const parts = [r.package.format, `${r.package.fileCount} ${r.package.fileCount === 1 ? "file" : "files"}`];
  const size = formatBytes(r.package.bytes);
  if (size !== "") parts.push(size);
  return `${r.package.source} · ${parts.join(" · ")}`;
}

function identityLine(r: ScanResult): string {
  const bits: string[] = [];
  if (r.identity.name !== undefined) bits.push(r.identity.name);
  if (r.identity.version !== undefined) bits.push(`v${r.identity.version}`);
  if (r.identity.manifestVersion !== undefined) bits.push(`MV${r.identity.manifestVersion}`);
  if (r.identity.crxId !== undefined) bits.push(`id ${r.identity.crxId}`);
  if (r.identity.geckoId !== undefined) bits.push(`gecko ${r.identity.geckoId}`);
  return bits.length > 0 ? bits.join(" · ") : "(no identity information)";
}

/** The full `crxray scan` text report. */
export function renderScan(r: ScanResult): string {
  const out: string[] = [];
  out.push(`crxray ${VERSION} — static extension audit`);
  out.push("");
  out.push(`package   ${packageLine(r)}`);
  if (r.package.sha256 !== undefined) out.push(`sha256    ${r.package.sha256}`);
  out.push(`identity  ${identityLine(r)}`);
  out.push(`risk      ${r.risk.score}/100 · ${r.risk.level.toUpperCase()}`);
  const breakdown = Object.entries(r.risk.byCategory)
    .filter(([, points]) => points > 0)
    .map(([category, points]) => `${category} ${points}`)
    .join(" · ");
  if (breakdown !== "") out.push(`breakdown ${breakdown}`);
  out.push("");

  out.push(`findings (${r.findings.length})`);
  if (r.findings.length === 0) {
    out.push("  none — nothing in the rubric fired");
  } else {
    const rows: string[][] = [["SEVERITY", "RULE", "LOCATION", "FINDING"]];
    for (const f of r.findings) {
      const location = f.file === undefined ? "-" : f.line === undefined ? f.file : `${f.file}:${f.line}`;
      rows.push([f.severity, f.rule, truncate(location, 28), truncate(f.title, 60)]);
    }
    out.push(table(rows));
  }

  if (r.permissions.length > 0) {
    out.push("");
    out.push(`permissions (${r.permissions.length})`);
    const rows: string[][] = [["GRADE", "KIND", "PERMISSION", "WHY IT MATTERS"]];
    for (const p of r.permissions) {
      rows.push([p.severity, p.kind, truncate(p.permission, 32), truncate(p.reason, 64)]);
    }
    out.push(table(rows));
  }

  const flagged = r.endpoints.filter((e) => e.kind !== "plain" && e.kind !== "loopback");
  if (flagged.length > 0) {
    out.push("");
    out.push(`endpoints (${flagged.length} flagged of ${r.endpoints.length} total — see \`crxray urls\`)`);
    const rows: string[][] = [["KIND", "HOST", "URL"]];
    for (const e of flagged) {
      rows.push([
        e.kind === "tracker" ? `tracker:${e.trackerCategory}` : e.kind,
        truncate(e.host, 36),
        truncate(e.url, 56),
      ]);
    }
    out.push(table(rows));
  }
  return out.join("\n");
}

/** The `crxray manifest` view: normalized manifest facts + grades. */
export function renderManifest(r: ScanResult, m: ManifestSummary): string {
  const out: string[] = [];
  out.push(`manifest    ${identityLine(r)}`);
  out.push(`source      ${packageLine(r)}`);
  const bg = m.background.kind === "none" ? "none" : `${m.background.kind}: ${m.background.files.join(", ")}`;
  out.push(`background  ${bg}`);
  if (m.updateUrl !== undefined) out.push(`update      ${m.updateUrl}`);
  if (m.cspExtensionPages !== undefined) out.push(`csp         ${truncate(m.cspExtensionPages, 100)}`);
  out.push("");
  out.push(`permissions (${r.permissions.length})`);
  if (r.permissions.length === 0) {
    out.push("  none declared");
  } else {
    const rows: string[][] = [["GRADE", "KIND", "PERMISSION", "WHY IT MATTERS"]];
    for (const p of r.permissions) {
      rows.push([p.severity, p.kind, truncate(p.permission, 32), truncate(p.reason, 64)]);
    }
    out.push(table(rows));
  }
  if (m.contentScripts.length > 0) {
    out.push("");
    out.push(`content scripts (${m.contentScripts.length})`);
    const rows: string[][] = [["MATCHES", "SCRIPTS"]];
    for (const cs of m.contentScripts) {
      rows.push([truncate(cs.matches.join(", "), 44), truncate(cs.js.join(", "), 52)]);
    }
    out.push(table(rows));
  }
  if (m.webAccessibleResources.length > 0) {
    out.push("");
    out.push(`web-accessible resources: ${truncate(m.webAccessibleResources.join(", "), 90)}`);
  }
  return out.join("\n");
}

/** The `crxray urls` view: every endpoint, flagged or not. */
export function renderUrls(r: ScanResult): string {
  const out: string[] = [];
  out.push(`endpoints (${r.endpoints.length}) in ${r.package.source}`);
  if (r.endpoints.length === 0) {
    out.push("  none — no URL literals in the package");
    return out.join("\n");
  }
  const rows: string[][] = [["KIND", "HOST", "URL", "FILES"]];
  for (const e of r.endpoints) {
    rows.push([
      e.kind === "tracker" ? `tracker:${e.trackerCategory}` : e.kind,
      truncate(e.host, 36),
      truncate(e.url, 56),
      truncate(e.files.join(", "), 40),
    ]);
  }
  out.push(table(rows));
  return out.join("\n");
}

/** The `crxray id` view: identity evidence only. */
export function renderId(r: ScanResult): string {
  const rows: string[][] = [];
  rows.push(["source", r.package.source]);
  rows.push(["format", r.package.format]);
  if (r.package.sha256 !== undefined) rows.push(["sha256", r.package.sha256]);
  if (r.identity.crxId !== undefined) rows.push(["crx id", r.identity.crxId]);
  if (r.identity.geckoId !== undefined) rows.push(["gecko id", r.identity.geckoId]);
  if (r.identity.name !== undefined) rows.push(["name", r.identity.name]);
  if (r.identity.version !== undefined) rows.push(["version", r.identity.version]);
  if (r.identity.manifestVersion !== undefined) rows.push(["manifest", `MV${r.identity.manifestVersion}`]);
  if (r.identity.proofs !== undefined) {
    rows.push([
      "proofs",
      `${r.identity.proofs.rsa} rsa, ${r.identity.proofs.ecdsa} ecdsa (present, not verified)`,
    ]);
  }
  return table(rows, "");
}
