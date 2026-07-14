/**
 * Tiny declarative argv parser. Commands own their flag sets; anything
 * undeclared is a hard usage error (exit 2) rather than a silent typo —
 * `--fail-onn high` must never scan with the default threshold.
 */

export class UsageError extends Error {}

export type CommandName = "scan" | "unpack" | "manifest" | "urls" | "id";

/** Parsed command line. */
export interface ParsedArgs {
  command: CommandName;
  positionals: string[];
  flags: Record<string, string | boolean>;
  help: boolean;
  version: boolean;
}

interface FlagSpec {
  takesValue: boolean;
  short?: string;
}

const GLOBAL_FLAGS: Record<string, FlagSpec> = {
  help: { takesValue: false, short: "h" },
  version: { takesValue: false, short: "V" },
};

const COMMAND_FLAGS: Record<CommandName, Record<string, FlagSpec>> = {
  scan: {
    json: { takesValue: false },
    "fail-on": { takesValue: true },
  },
  unpack: {
    out: { takesValue: true, short: "o" },
    force: { takesValue: false, short: "f" },
  },
  manifest: { json: { takesValue: false } },
  urls: { json: { takesValue: false } },
  id: { json: { takesValue: false } },
};

const COMMANDS = Object.keys(COMMAND_FLAGS) as CommandName[];

function isCommand(word: string): word is CommandName {
  return (COMMANDS as string[]).includes(word);
}

/**
 * Parse argv (already stripped of node + script). A leading word that is
 * not a known command is treated as an input path for the default
 * command, so `crxray extension.crx` just works.
 */
export function parseArgs(argv: string[]): ParsedArgs {
  let command: CommandName = "scan";
  let rest = argv;
  const first = argv[0];
  // A leading word that is not a known command stays in `rest` as the
  // input path for the default `scan` command.
  if (first !== undefined && !first.startsWith("-") && isCommand(first)) {
    command = first;
    rest = argv.slice(1);
  }

  const specs: Record<string, FlagSpec> = { ...GLOBAL_FLAGS, ...COMMAND_FLAGS[command] };
  const shortToLong = new Map<string, string>();
  for (const [long, spec] of Object.entries(specs)) {
    if (spec.short !== undefined) shortToLong.set(spec.short, long);
  }

  const positionals: string[] = [];
  const flags: Record<string, string | boolean> = {};
  let i = 0;
  while (i < rest.length) {
    const arg = rest[i] as string;
    if (arg === "--") {
      positionals.push(...rest.slice(i + 1));
      break;
    }
    if (arg.startsWith("--")) {
      const eq = arg.indexOf("=");
      const name = eq === -1 ? arg.slice(2) : arg.slice(2, eq);
      const spec = specs[name];
      if (spec === undefined) throw new UsageError(`unknown option: --${name}`);
      if (spec.takesValue) {
        const value = eq !== -1 ? arg.slice(eq + 1) : rest[++i];
        if (value === undefined) throw new UsageError(`option --${name} needs a value`);
        flags[name] = value;
      } else {
        if (eq !== -1) throw new UsageError(`option --${name} does not take a value`);
        flags[name] = true;
      }
    } else if (arg.startsWith("-") && arg.length > 1) {
      const long = shortToLong.get(arg.slice(1));
      if (long === undefined) throw new UsageError(`unknown option: ${arg}`);
      const spec = specs[long] as FlagSpec;
      if (spec.takesValue) {
        const value = rest[++i];
        if (value === undefined) throw new UsageError(`option ${arg} needs a value`);
        flags[long] = value;
      } else {
        flags[long] = true;
      }
    } else {
      positionals.push(arg);
    }
    i++;
  }

  return {
    command,
    positionals,
    flags,
    help: flags.help === true,
    version: flags.version === true,
  };
}

export const USAGE = `crxray — static forensics for browser extension packages (CRX, XPI, ZIP)

Usage:
  crxray scan <file|dir> [--json] [--fail-on <level>]
  crxray unpack <file> [-o <dir>] [--force]
  crxray manifest <file|dir> [--json]
  crxray urls <file|dir> [--json]
  crxray id <file|dir> [--json]
  crxray --version | --help

Commands:
  scan       full audit: permissions, remote code, obfuscation,
             endpoints, archive hygiene — scored by the risk rubric
             (a bare "crxray <file>" runs scan)
  unpack     extract the payload safely (zip-slip entries are refused)
  manifest   normalized manifest facts and graded permissions
  urls       every endpoint literal found in the package, classified
  id         identity evidence: crx id, gecko id, sha256, signatures

Options:
  --json            machine-readable output (scan, manifest, urls, id)
  --fail-on LEVEL   exit 1 when risk level is at or above LEVEL:
                    minimal|low|medium|high|critical|never (default: high)
  -o, --out DIR     unpack destination (default: <name>-unpacked)
  -f, --force       unpack into a non-empty directory
  -V, --version     print the version
  -h, --help        this help

Exit codes:
  0  ok
  1  scan risk at/above --fail-on, or unpack refused unsafe entries
  2  usage or input error
`;
