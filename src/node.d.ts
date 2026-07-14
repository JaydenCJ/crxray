/**
 * Minimal ambient declarations for the handful of Node.js built-ins this
 * project uses. Declaring them in-repo keeps `typescript` the only
 * devDependency (no `@types/node`); the surface below is intentionally
 * restricted to exactly what `src/` calls, so a typo against a real Node
 * API still fails to compile.
 */

/** The slice of Node's Buffer that crxray relies on. */
interface Bytes {
  readonly length: number;
  [index: number]: number;
  subarray(start?: number, end?: number): Bytes;
  readUInt16LE(offset: number): number;
  readUInt32LE(offset: number): number;
  toString(encoding?: "utf8" | "latin1" | "base64" | "hex"): string;
}

declare var Buffer: {
  from(data: string, encoding?: "utf8" | "latin1" | "base64" | "hex"): Bytes;
  concat(list: Bytes[]): Bytes;
  alloc(size: number): Bytes;
  byteLength(data: string): number;
  isBuffer(value: unknown): value is Bytes;
};

declare module "node:fs" {
  export interface Dirent {
    name: string;
    isDirectory(): boolean;
    isFile(): boolean;
  }
  export interface Stats {
    size: number;
    isDirectory(): boolean;
    isFile(): boolean;
  }
  /** No-encoding overload returns a Buffer; "utf8" returns a string. */
  export function readFileSync(path: string): Bytes;
  export function readFileSync(path: string, encoding: "utf8"): string;
  export function writeFileSync(path: string, data: string | Bytes): void;
  export function mkdirSync(path: string, options: { recursive: boolean }): void;
  export function readdirSync(path: string, options: { withFileTypes: true }): Dirent[];
  export function statSync(path: string): Stats;
  export function existsSync(path: string): boolean;
}

declare module "node:path" {
  export function join(...parts: string[]): string;
  export function resolve(...parts: string[]): string;
  export function dirname(path: string): string;
  export function basename(path: string, suffix?: string): string;
  export function extname(path: string): string;
}

declare module "node:zlib" {
  export function inflateRawSync(data: Bytes): Bytes;
}

declare module "node:crypto" {
  interface Hash {
    update(data: string | Bytes): Hash;
    digest(): Bytes;
    digest(encoding: "hex"): string;
  }
  export function createHash(algorithm: "sha256"): Hash;
}

declare var process: {
  argv: string[];
  exitCode: number | undefined;
  exit(code?: number): never;
  cwd(): string;
  stdout: { write(chunk: string): boolean };
  stderr: { write(chunk: string): boolean };
  env: Record<string, string | undefined>;
};
