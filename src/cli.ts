#!/usr/bin/env node
/**
 * CLI entry point — the only module that touches the filesystem or the
 * process. Everything it prints comes from pure modules; everything it
 * reads goes through openArchive()/packageFromDirectory().
 *
 * Exit codes: 0 ok · 1 scan risk at/above --fail-on · 2 usage or input
 * error. No network. Ever.
 */
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { basename, dirname, extname, join } from "node:path";

import type { PackageFile, PackageInput, RiskLevel } from "./types.js";
import { RISK_LEVELS } from "./types.js";
import { openArchive, scanPackage, ScanError, type ScanResult } from "./scan.js";
import { parseManifest, ManifestError } from "./manifest.js";
import { sanitizeEntryPath } from "./zip.js";
import { parseArgs, UsageError, USAGE } from "./cliargs.js";
import { renderScan, renderManifest, renderUrls, renderId } from "./report.js";
import { levelRank } from "./rubric.js";
import { VERSION } from "./version.js";

function walkDirectory(root: string, rel: string, files: PackageFile[]): void {
  const abs = rel === "" ? root : join(root, rel);
  for (const entry of readdirSync(abs, { withFileTypes: true })) {
    // .git inside an unpacked dev directory is noise, not extension code.
    if (entry.name === ".git") continue;
    const childRel = rel === "" ? entry.name : `${rel}/${entry.name}`;
    if (entry.isDirectory()) {
      walkDirectory(root, childRel, files);
    } else if (entry.isFile()) {
      files.push({ path: childRel, data: readFileSync(join(root, childRel)), crcOk: true });
    }
  }
}

/** Open an unpacked extension directory as a package. */
function packageFromDirectory(path: string): PackageInput {
  const files: PackageFile[] = [];
  walkDirectory(path, "", files);
  files.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  return { source: path, format: "directory", files };
}

/** Load a package from a file or directory path; exit-2 errors otherwise. */
function loadPackage(path: string | undefined, allowDirectory: boolean): PackageInput {
  if (path === undefined) throw new UsageError("missing input path (see --help)");
  if (!existsSync(path)) throw new ScanError(`no such file or directory: ${path}`);
  if (statSync(path).isDirectory()) {
    if (!allowDirectory) throw new UsageError(`${path} is already a directory — nothing to unpack`);
    return packageFromDirectory(path);
  }
  return openArchive(readFileSync(path), path);
}

function parseFailOn(value: string | boolean | undefined): RiskLevel | "never" {
  if (value === undefined) return "high";
  if (typeof value !== "string") throw new UsageError("--fail-on needs a value");
  if (value === "never" || (RISK_LEVELS as string[]).includes(value)) {
    return value as RiskLevel | "never";
  }
  throw new UsageError(`--fail-on must be one of ${RISK_LEVELS.join("|")}|never, got "${value}"`);
}

function print(text: string): void {
  process.stdout.write(`${text}\n`);
}

function toJson(value: unknown): string {
  return JSON.stringify(value, null, 2);
}

function commandScan(result: ScanResult, json: boolean, failOn: RiskLevel | "never"): number {
  print(json ? toJson(result) : renderScan(result));
  if (failOn !== "never" && levelRank(result.risk.level) >= levelRank(failOn)) return 1;
  return 0;
}

function commandUnpack(pkg: PackageInput, outDir: string, force: boolean): number {
  if (existsSync(outDir)) {
    if (!statSync(outDir).isDirectory()) throw new ScanError(`${outDir} exists and is not a directory`);
    if (readdirSync(outDir, { withFileTypes: true }).length > 0 && !force) {
      throw new ScanError(`${outDir} is not empty (use --force to unpack anyway)`);
    }
  }
  let written = 0;
  let refused = 0;
  for (const file of pkg.files) {
    const safe = sanitizeEntryPath(file.path);
    if (safe === null) {
      refused++;
      process.stderr.write(`crxray: refused unsafe entry path: ${file.path}\n`);
      continue;
    }
    const target = join(outDir, ...safe.split("/"));
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, file.data);
    written++;
  }
  const entries = `${refused} unsafe ${refused === 1 ? "entry" : "entries"} refused`;
  print(`unpacked ${written} ${written === 1 ? "file" : "files"} to ${outDir}${refused > 0 ? ` (${entries})` : ""}`);
  return refused > 0 ? 1 : 0;
}

function findManifestText(pkg: PackageInput): string | null {
  const file = pkg.files.find((f) => sanitizeEntryPath(f.path) === "manifest.json");
  return file === null || file === undefined ? null : file.data.toString("utf8");
}

/** Run the CLI; returns the process exit code. */
export function main(argv: string[]): number {
  let args;
  try {
    args = parseArgs(argv);
  } catch (err) {
    process.stderr.write(`crxray: ${err instanceof Error ? err.message : String(err)}\n`);
    return 2;
  }
  if (args.version) {
    print(VERSION);
    return 0;
  }
  if (args.help) {
    print(USAGE.trimEnd());
    return 0;
  }

  try {
    const input = args.positionals[0];
    switch (args.command) {
      case "scan": {
        const failOn = parseFailOn(args.flags["fail-on"]);
        const pkg = loadPackage(input, true);
        return commandScan(scanPackage(pkg), args.flags.json === true, failOn);
      }
      case "unpack": {
        const pkg = loadPackage(input, false);
        const fallback = `${basename(input as string, extname(input as string))}-unpacked`;
        const outDir = typeof args.flags.out === "string" ? args.flags.out : fallback;
        return commandUnpack(pkg, outDir, args.flags.force === true);
      }
      case "manifest": {
        const pkg = loadPackage(input, true);
        const text = findManifestText(pkg);
        if (text === null) throw new ScanError(`${pkg.source} has no top-level manifest.json`);
        const manifest = parseManifest(text);
        const result = scanPackage(pkg);
        if (args.flags.json === true) {
          print(toJson({ identity: result.identity, manifest, permissions: result.permissions }));
        } else {
          print(renderManifest(result, manifest));
        }
        return 0;
      }
      case "urls": {
        const result = scanPackage(loadPackage(input, true));
        print(args.flags.json === true ? toJson(result.endpoints) : renderUrls(result));
        return 0;
      }
      case "id": {
        const result = scanPackage(loadPackage(input, true));
        if (args.flags.json === true) {
          print(toJson({ package: result.package, identity: result.identity }));
        } else {
          print(renderId(result));
        }
        return 0;
      }
    }
  } catch (err) {
    if (err instanceof UsageError || err instanceof ScanError || err instanceof ManifestError) {
      process.stderr.write(`crxray: ${err.message}\n`);
      return 2;
    }
    if (err instanceof Error && "code" in err && typeof err.code === "string") {
      process.stderr.write(`crxray: ${err.message}\n`);
      return 2;
    }
    throw err;
  }
  return 0;
}

// Set the exit code instead of calling process.exit(): an immediate exit
// can drop buffered stdout when it is a pipe, truncating piped reports.
process.exitCode = main(process.argv.slice(2));
