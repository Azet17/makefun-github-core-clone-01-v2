// GitHub-compatible git forge — one Node process, standard library only.
//
// The forge serves the full GitHub surface the conformance suite exercises:
//   * smart-HTTP git (upload-pack v2, receive-pack v0) with pack files
//   * REST v3 (repositories, branches, commits, refs, contents, issues, pulls)
//   * GraphQL v4 (a fixed-document dispatcher over the same store)
//   * MCP (streamable HTTP, modern 2026-07-28 era with a legacy fallback)
//   * the make.fun lifecycle: register, then poll /done, then exit
//
// Design notes worth knowing before touching anything:
//   * One in-memory vault holds every repository. No git binary, no disk.
//   * Every object is stored once, by its SHA-1, and verified on read.
//   * Packs are built plain (no deltas) and cached per (repository, tip, depth).
//   * The hot paths (issue read/write, pack fetch, clone) avoid re-serializing
//     anything they have already built: JSON and pack bytes are cached and
//     invalidated only when the underlying record changes.

import * as nodeHttp from 'node:http';
import * as nodeCrypto from 'node:crypto';
import * as nodeZlib from 'node:zlib';

// ---------------------------------------------------------------------------
// Identity and constants
// ---------------------------------------------------------------------------

/** The account the shop token names. */
const VIEWER_LOGIN = 'adaiversen';
const VIEWER_ID = 1000;
const VIEWER_NAME = 'ada iversen';
const VIEWER_EMAIL = 'adaiversen@example.invalid';
/** The teammate login the scenario reserves (a repository under this name is foreign). */
const TEAMMATE_LOGIN = 'quinnkeller';
/** The stranger login the scenario reserves. */
const STRANGER_LOGIN = 'olgabauer';
/** The seeded organisation name (never an owner of a repository here). */
const ORG_LOGIN = 'faint-meadow-org';

/** The all-zero object id. */
const ZERO_OID = '0000000000000000000000000000000000000000';
/** The six labels every repository is born with. */
const SEED_LABELS: ReadonlyArray<{ readonly name: string; readonly color: string }> = [
  { name: 'bug', color: 'd73a4a' },
  { name: 'enhancement', color: 'a2eeef' },
  { name: 'documentation', color: '0075ca' },
  { name: 'question', color: 'd876e3' },
  { name: 'good first issue', color: '7057ff' },
  { name: 'help wanted', color: '008672' },
];
/** GitHub's own pagination default. */
const DEFAULT_PER_PAGE = 30;
/** Largest pkt-line payload chunk for sideband pack data. */
const SIDEBAND_CHUNK = 65515;
/** The forge's agent string, advertised on the git wire. */
const FORGE_AGENT = 'forge/1.0';

/** The bearer token the environment hands us; empty means "accept any bearer". */
function shopToken(): string {
  return process.env.MAKEFUN_SHOP_TOKEN ?? '';
}

function envUrl(): string {
  return process.env.MAKEFUN_ENV_URL ?? '';
}

// ---------------------------------------------------------------------------
// Small utilities
// ---------------------------------------------------------------------------

function sha1Hex(data: Buffer | string): string {
  return nodeCrypto.createHash('sha1').update(data).digest('hex');
}

function base64UrlEncode(text: string): string {
  return Buffer.from(text, 'utf8').toString('base64url');
}

function base64UrlDecode(text: string): string | null {
  try {
    return Buffer.from(text, 'base64url').toString('utf8');
  } catch {
    return null;
  }
}

function isHex40(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{40}$/.test(value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function asString(value: unknown, fallback = ''): string {
  return typeof value === 'string' ? value : fallback;
}

function asNumber(value: unknown, fallback = 0): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : fallback;
}

function nowIso(): string {
  return new Date().toISOString();
}

function nowEpoch(): number {
  return Math.floor(Date.now() / 1000);
}

/** A short random suffix for request ids. */
function randomSuffix(): string {
  return nodeCrypto.randomBytes(6).toString('hex');
}

/** JSON.stringify that never throws on the shapes we build. */
function toJson(value: unknown): string {
  return JSON.stringify(value) ?? 'null';
}

function parseJsonBody(text: string): unknown {
  if (text.trim() === '') return {};
  return JSON.parse(text);
}

/** Split a URL path into its segments, dropping empty ones. */
function splitPath(path: string): string[] {
  return path.split('/').filter((part) => part.length > 0);
}

function decodeSegment(segment: string): string {
  try {
    return decodeURIComponent(segment);
  } catch {
    return segment;
  }
}

/** Parse a query string into a plain object (first value wins). */
function parseQuery(query: string): Record<string, string> {
  const out: Record<string, string> = {};
  if (!query) return out;
  for (const pair of query.split('&')) {
    if (!pair) continue;
    const eq = pair.indexOf('=');
    const key = eq < 0 ? pair : pair.slice(0, eq);
    const value = eq < 0 ? '' : pair.slice(eq + 1);
    const decodedKey = decodeSegment(key.replace(/\+/g, ' '));
    if (!(decodedKey in out)) out[decodedKey] = decodeSegment(value.replace(/\+/g, ' '));
  }
  return out;
}

function queryInt(query: Record<string, string>, key: string, fallback: number): number {
  const raw = query[key];
  if (raw === undefined) return fallback;
  const parsed = Number.parseInt(raw, 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

/** Clamp a page size the way the list endpoints do. */
function pageSize(query: Record<string, string>): number {
  const size = queryInt(query, 'per_page', DEFAULT_PER_PAGE);
  if (size < 1) return 1;
  if (size > 100) return 100;
  return size;
}

function pageNumber(query: Record<string, string>): number {
  const page = queryInt(query, 'page', 1);
  return page < 1 ? 1 : page;
}

// ---------------------------------------------------------------------------
// pkt-line framing (the git wire format)
// ---------------------------------------------------------------------------

function encodePktLine(payload: string | Buffer): Buffer {
  const body = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const total = body.length + 4;
  const header = total.toString(16).padStart(4, '0');
  return Buffer.concat([Buffer.from(header, 'ascii'), body]);
}

const FLUSH_PACKET = Buffer.from('0000', 'ascii');
const DELIM_PACKET = Buffer.from('0001', 'ascii');

function encodePktLines(items: ReadonlyArray<string | Buffer | 'flush' | 'delim'>): Buffer {
  const parts: Buffer[] = [];
  for (const item of items) {
    if (item === 'flush') parts.push(FLUSH_PACKET);
    else if (item === 'delim') parts.push(DELIM_PACKET);
    else parts.push(encodePktLine(item));
  }
  return Buffer.concat(parts);
}

type PktKind = 'data' | 'flush' | 'delim';

interface DecodedPacket {
  readonly kind: PktKind;
  readonly payload: Buffer;
}

/**
 * Decode pkt-lines from the front of `buffer`. Stops at the first flush and
 * returns the byte offset just past it, or null when the buffer ends first.
 * Everything after a flush is raw payload (a pack file), not pkt-lines.
 */
function decodeUntilFlush(buffer: Buffer): { packets: DecodedPacket[]; afterFlush: number } | null {
  const packets: DecodedPacket[] = [];
  let offset = 0;
  while (offset + 4 <= buffer.length) {
    const head = buffer.subarray(offset, offset + 4).toString('ascii');
    if (head === '0000') return { packets, afterFlush: offset + 4 };
    if (head === '0001') {
      packets.push({ kind: 'delim', payload: Buffer.alloc(0) });
      offset += 4;
      continue;
    }
    const length = Number.parseInt(head, 16);
    if (!Number.isFinite(length) || length < 4 || offset + length > buffer.length) return null;
    packets.push({ kind: 'data', payload: buffer.subarray(offset + 4, offset + length) });
    offset += length;
  }
  return null;
}

/** Decode a whole buffer of pkt-lines; throws on truncation. */
function decodeAllPackets(buffer: Buffer): DecodedPacket[] {
  const packets: DecodedPacket[] = [];
  let offset = 0;
  while (offset < buffer.length) {
    if (offset + 4 > buffer.length) throw new Error('truncated pkt-line');
    const head = buffer.subarray(offset, offset + 4).toString('ascii');
    if (head === '0000') {
      packets.push({ kind: 'flush', payload: Buffer.alloc(0) });
      offset += 4;
      continue;
    }
    if (head === '0001') {
      packets.push({ kind: 'delim', payload: Buffer.alloc(0) });
      offset += 4;
      continue;
    }
    const length = Number.parseInt(head, 16);
    if (!Number.isFinite(length) || length < 4 || offset + length > buffer.length) {
      throw new Error('truncated pkt-line');
    }
    packets.push({ kind: 'data', payload: buffer.subarray(offset + 4, offset + length) });
    offset += length;
  }
  return packets;
}

// ---------------------------------------------------------------------------
// Git objects: hashing, trees, commits, tags
// ---------------------------------------------------------------------------

type ObjectKind = 'commit' | 'tree' | 'blob' | 'tag';

const KIND_NUMBERS: Record<ObjectKind, number> = { commit: 1, tree: 2, blob: 3, tag: 4 };
const NUMBER_KINDS: Record<number, ObjectKind> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };

interface GitObject {
  readonly kind: ObjectKind;
  readonly bytes: Buffer;
}

/** The id of an object, exactly as git computes it. */
function hashObject(kind: ObjectKind, bytes: Buffer): string {
  const header = Buffer.from(`${kind} ${bytes.length}\0`, 'utf8');
  return sha1Hex(Buffer.concat([header, bytes]));
}

interface TreeEntry {
  readonly mode: string;
  readonly name: string;
  readonly oid: string;
}

/** Parse a tree object into its entries, in stored order. */
function parseTree(data: Buffer): TreeEntry[] {
  const entries: TreeEntry[] = [];
  let offset = 0;
  while (offset < data.length) {
    const space = data.indexOf(0x20, offset);
    if (space < 0) throw new Error('tree entry has no mode separator');
    const nul = data.indexOf(0x00, space + 1);
    if (nul < 0 || nul + 21 > data.length) throw new Error('tree entry is truncated');
    const mode = data.subarray(offset, space).toString('ascii');
    const name = data.subarray(space + 1, nul).toString('utf8');
    const oid = data.subarray(nul + 1, nul + 21).toString('hex');
    if (!/^[0-7]+$/.test(mode)) throw new Error(`tree entry mode ${JSON.stringify(mode)} is not octal`);
    entries.push({ mode, name, oid });
    offset = nul + 21;
  }
  return entries;
}

/** git's tree-entry sort: byte order of the name, a directory as if it ended in '/'. */
function compareTreeEntries(a: TreeEntry, b: TreeEntry): number {
  const left = Buffer.from(a.mode === '40000' ? `${a.name}/` : a.name, 'utf8');
  const right = Buffer.from(b.mode === '40000' ? `${b.name}/` : b.name, 'utf8');
  return Buffer.compare(left, right);
}

/** Build a tree object's bytes; entries are sorted the way git sorts them. */
function buildTree(entries: readonly TreeEntry[]): Buffer {
  const sorted = [...entries].sort(compareTreeEntries);
  const parts: Buffer[] = [];
  for (const entry of sorted) {
    parts.push(Buffer.from(`${entry.mode} ${entry.name}\0`, 'utf8'));
    parts.push(Buffer.from(entry.oid, 'hex'));
  }
  return Buffer.concat(parts);
}

interface CommitView {
  readonly tree: string;
  readonly parents: string[];
  readonly author: string;
  readonly committer: string;
  readonly message: string;
  readonly extra: Array<readonly [string, string]>;
}

/** Parse a commit object; refuses a malformed header layout. */
function parseCommit(data: Buffer): CommitView {
  const blank = data.indexOf('\n\n');
  const headerEnd = blank < 0 ? data.length : blank;
  const headerText = data.subarray(0, headerEnd).toString('utf8');
  const message = blank < 0 ? '' : data.subarray(blank + 2).toString('utf8');
  let tree = '';
  const parents: string[] = [];
  let author = '';
  let committer = '';
  const extra: Array<[string, string]> = [];
  for (const line of headerText.split('\n')) {
    if (!line) continue;
    const space = line.indexOf(' ');
    const key = space < 0 ? line : line.slice(0, space);
    const value = space < 0 ? '' : line.slice(space + 1);
    if (key === 'tree') tree = value;
    else if (key === 'parent') parents.push(value);
    else if (key === 'author') author = value;
    else if (key === 'committer') committer = value;
    else extra.push([key, value]);
  }
  if (!isHex40(tree)) throw new Error('commit has no valid tree header');
  for (const parent of parents) if (!isHex40(parent)) throw new Error('commit has a bad parent id');
  return { tree, parents, author, committer, message, extra };
}

/** Build a commit object's bytes (tree, parents, author, committer, message). */
function buildCommit(tree: string, parents: readonly string[], message: string, when: number): Buffer {
  const who = `${VIEWER_NAME} <${VIEWER_EMAIL}> ${when} +0000`;
  const lines = [`tree ${tree}`];
  for (const parent of parents) lines.push(`parent ${parent}`);
  lines.push(`author ${who}`, `committer ${who}`, '');
  return Buffer.from(`${lines.join('\n')}\n${message}`, 'utf8');
}

interface TagView {
  readonly object: string;
  readonly type: ObjectKind;
  readonly tag: string;
  readonly tagger: string;
  readonly message: string;
}

/** Parse an annotated tag object. */
function parseTag(data: Buffer): TagView {
  const blank = data.indexOf('\n\n');
  const headerEnd = blank < 0 ? data.length : blank;
  const headers = new Map<string, string>();
  for (const line of data.subarray(0, headerEnd).toString('utf8').split('\n')) {
    if (!line) continue;
    const space = line.indexOf(' ');
    if (space < 0) throw new Error(`tag header ${JSON.stringify(line)} has no value`);
    headers.set(line.slice(0, space), line.slice(space + 1));
  }
  const object = headers.get('object') ?? '';
  const type = headers.get('type') ?? '';
  if (!isHex40(object)) throw new Error('tag has no valid object header');
  if (type !== 'commit' && type !== 'tree' && type !== 'blob' && type !== 'tag') {
    throw new Error(`tag has bad type ${JSON.stringify(type)}`);
  }
  return {
    object,
    type,
    tag: headers.get('tag') ?? '',
    tagger: headers.get('tagger') ?? '',
    message: blank < 0 ? '' : data.subarray(blank + 2).toString('utf8'),
  };
}

// ---------------------------------------------------------------------------
// Pack files: write (plain objects), read (plain + ofs/ref deltas)
// ---------------------------------------------------------------------------

/** The object-header varint git writes before each object in a pack. */
function packObjectHeader(typeNum: number, size: number): Buffer {
  const bytes: number[] = [];
  let first = (typeNum << 4) | (size & 15);
  size >>>= 4;
  while (size > 0) {
    bytes.push(first | 0x80);
    first = size & 0x7f;
    size >>>= 7;
  }
  bytes.push(first);
  return Buffer.from(bytes);
}

/**
 * Build a pack file (version 2, plain objects, no deltas) from the given
 * objects, in the order supplied. The trailer is the SHA-1 of all prior bytes.
 */
function buildPack(objects: readonly GitObject[]): Buffer {
  const parts: Buffer[] = [];
  const header = Buffer.alloc(12);
  header.write('PACK', 0, 'ascii');
  header.writeUInt32BE(2, 4);
  header.writeUInt32BE(objects.length, 8);
  parts.push(header);
  for (const object of objects) {
    const typeNum = KIND_NUMBERS[object.kind];
    parts.push(packObjectHeader(typeNum, object.bytes.length));
    parts.push(nodeZlib.deflateSync(object.bytes));
  }
  const withoutTrailer = Buffer.concat(parts);
  const trailer = nodeCrypto.createHash('sha1').update(withoutTrailer).digest();
  return Buffer.concat([withoutTrailer, trailer]);
}

/** Read a git delta's variable-length size field; returns [value, nextOffset]. */
function readDeltaVarint(data: Buffer, offset: number): [number, number] {
  let value = 0;
  let shift = 0;
  let at = offset;
  for (;;) {
    if (at >= data.length) throw new Error('delta varint is truncated');
    const byte = data[at];
    at += 1;
    value |= (byte & 0x7f) << shift;
    shift += 7;
    if ((byte & 0x80) === 0) break;
  }
  return [value, at];
}

/** Apply a git delta to a base object's bytes. */
function applyDelta(base: Buffer, delta: Buffer): Buffer {
  const [sourceSize, afterSource] = readDeltaVarint(delta, 0);
  if (sourceSize !== base.length) throw new Error('delta base size mismatch');
  const [targetSize, afterTarget] = readDeltaVarint(delta, afterSource);
  const out: Buffer[] = [];
  let produced = 0;
  let at = afterTarget;
  while (at < delta.length) {
    const op = delta[at];
    at += 1;
    if ((op & 0x80) !== 0) {
      let offset = 0;
      let size = 0;
      for (let bit = 0; bit < 4; bit += 1) {
        if ((op & (1 << bit)) !== 0) {
          if (at >= delta.length) throw new Error('delta copy is truncated');
          offset |= delta[at] << (bit * 8);
          at += 1;
        }
      }
      for (let bit = 0; bit < 3; bit += 1) {
        if ((op & (0x10 << bit)) !== 0) {
          if (at >= delta.length) throw new Error('delta copy is truncated');
          size |= delta[at] << (bit * 8);
          at += 1;
        }
      }
      if (size === 0) size = 0x10000;
      if (offset + size > base.length) throw new Error('delta copy runs past the base');
      out.push(base.subarray(offset, offset + size));
      produced += size;
    } else if (op !== 0) {
      if (at + op > delta.length) throw new Error('delta insert is truncated');
      out.push(delta.subarray(at, at + op));
      produced += op;
      at += op;
    } else {
      throw new Error('delta has a zero opcode');
    }
  }
  if (produced !== targetSize) throw new Error('delta target size mismatch');
  return Buffer.concat(out);
}

interface ParsedPack {
  readonly objects: Map<string, GitObject>;
  readonly deltaCount: number;
}

/**
 * Parse a pack file. Deltas resolve against objects earlier in the same pack
 * or against `resolveBase` (objects the peer already holds, for thin packs).
 * Throws on a bad header, a bad checksum, or an unresolvable delta.
 */
function parsePack(pack: Buffer, resolveBase?: (oid: string) => GitObject | undefined): ParsedPack {
  if (pack.length < 32) throw new Error('pack is too short');
  if (pack.subarray(0, 4).toString('ascii') !== 'PACK') throw new Error('pack has a bad signature');
  const version = pack.readUInt32BE(4);
  if (version !== 2 && version !== 3) throw new Error(`pack version ${version} is not supported`);
  const count = pack.readUInt32BE(8);
  const expectedTrailer = nodeCrypto.createHash('sha1').update(pack.subarray(0, pack.length - 20)).digest('hex');
  const actualTrailer = pack.subarray(pack.length - 20).toString('hex');
  if (expectedTrailer !== actualTrailer) throw new Error('pack trailer does not match its bytes');

  const objects = new Map<string, GitObject>();
  const offsets = new Map<number, string>();
  const pending: Array<{ oid: string; kind: ObjectKind; bytes: Buffer }> = [];
  let deltaCount = 0;
  let offset = 12;
  const end = pack.length - 20;
  for (let index = 0; index < count; index += 1) {
    if (offset >= end) throw new Error('pack ends before its declared object count');
    const objectStart = offset;
    let byte = pack[offset];
    offset += 1;
    const typeNum = (byte >> 4) & 7;
    let size = byte & 15;
    let shift = 4;
    while ((byte & 0x80) !== 0) {
      if (offset >= end) throw new Error('pack object header is truncated');
      byte = pack[offset];
      offset += 1;
      size |= (byte & 0x7f) << shift;
      shift += 7;
    }
    if (typeNum === 6) {
      // ofs-delta: a negative offset varint points back to the base object.
      if (offset >= end) throw new Error('ofs-delta offset is truncated');
      let deltaByte = pack[offset];
      offset += 1;
      let baseOffset = deltaByte & 0x7f;
      while ((deltaByte & 0x80) !== 0) {
        if (offset >= end) throw new Error('ofs-delta offset is truncated');
        deltaByte = pack[offset];
        offset += 1;
        baseOffset = ((baseOffset + 1) << 7) | (deltaByte & 0x7f);
      }
      const inflated = inflateAt(pack, offset);
      const baseOid = offsets.get(objectStart - baseOffset);
      const base = baseOid === undefined ? undefined : objects.get(baseOid);
      if (base === undefined) throw new Error('ofs-delta base is missing');
      const bytes = applyDelta(base.bytes, inflated.bytes);
      const oid = hashObject(base.kind, bytes);
      objects.set(oid, { kind: base.kind, bytes });
      offsets.set(objectStart, oid);
      pending.push({ oid, kind: base.kind, bytes });
      offset = inflated.next;
      deltaCount += 1;
      continue;
    }
    let baseOid: string | undefined;
    if (typeNum === 7) {
      if (offset + 20 > end) throw new Error('ref-delta base id is truncated');
      baseOid = pack.subarray(offset, offset + 20).toString('hex');
      offset += 20;
    }
    const kind = NUMBER_KINDS[typeNum];
    if (kind === undefined) throw new Error(`pack object type ${typeNum} is not supported`);
    const inflated = inflateAt(pack, offset);
    if (inflated.bytes.length !== size) throw new Error('pack object size mismatch');
    offset = inflated.next;
    if (baseOid !== undefined) {
      const base = objects.get(baseOid) ?? resolveBase?.(baseOid);
      if (base === undefined) throw new Error('ref-delta base is missing');
      const bytes = applyDelta(base.bytes, inflated.bytes);
      const oid = hashObject(base.kind, bytes);
      objects.set(oid, { kind: base.kind, bytes });
      offsets.set(objectStart, oid);
      pending.push({ oid, kind: base.kind, bytes });
      deltaCount += 1;
      continue;
    }
    const oid = hashObject(kind, inflated.bytes);
    objects.set(oid, { kind, bytes: inflated.bytes });
    offsets.set(objectStart, oid);
    pending.push({ oid, kind, bytes: inflated.bytes });
  }
  void pending;
  return { objects, deltaCount };
}

/**
 * Inflate a deflate stream starting at `offset`. The engine reports exactly
 * how many compressed bytes it consumed, so the caller can continue after it.
 */
function inflateAt(buffer: Buffer, offset: number): { bytes: Buffer; next: number } {
  const sliced = buffer.subarray(offset);
  const result = nodeZlib.inflateSync(sliced, { info: true }) as unknown as {
    buffer: Buffer;
    engine: { bytesWritten: number };
  };
  const consumed = result.engine.bytesWritten;
  return { bytes: result.buffer, next: offset + consumed };
}

// ---------------------------------------------------------------------------
// Reachability: everything an object id pulls in behind it
// ---------------------------------------------------------------------------

/** Every object reachable from `roots`: commit → tree + parents, tree → entries, tag → target. */
function collectReachable(
  roots: Iterable<string>,
  lookup: (oid: string) => GitObject | undefined,
): Set<string> {
  const seen = new Set<string>();
  const stack: string[] = [...roots];
  while (stack.length > 0) {
    const oid = stack.pop() as string;
    if (seen.has(oid)) continue;
    const object = lookup(oid);
    if (object === undefined) continue;
    seen.add(oid);
    if (object.kind === 'commit') {
      const view = parseCommit(object.bytes);
      stack.push(view.tree);
      for (const parent of view.parents) stack.push(parent);
    } else if (object.kind === 'tree') {
      for (const entry of parseTree(object.bytes)) {
        if (entry.mode !== '160000') stack.push(entry.oid);
      }
    } else if (object.kind === 'tag') {
      stack.push(parseTag(object.bytes).object);
    }
  }
  return seen;
}

/**
 * Reachability that stops at the cut set: a commit in `cut` contributes
 * itself and its tree, but its parents are not followed. A shallow clone's
 * boundary commits are exactly such cut points — the peer holds the boundary
 * but not the history behind it, so the boundary's parents must not count
 * as already-held when a deepen asks for more.
 */
function collectReachableCut(
  roots: Iterable<string>,
  lookup: (oid: string) => GitObject | undefined,
  cut: ReadonlySet<string>,
): Set<string> {
  const seen = new Set<string>();
  const stack: string[] = [...roots];
  while (stack.length > 0) {
    const oid = stack.pop() as string;
    if (seen.has(oid)) continue;
    const object = lookup(oid);
    if (object === undefined) continue;
    seen.add(oid);
    if (object.kind === 'commit') {
      const view = parseCommit(object.bytes);
      stack.push(view.tree);
      if (!cut.has(oid)) for (const parent of view.parents) stack.push(parent);
    } else if (object.kind === 'tree') {
      for (const entry of parseTree(object.bytes)) {
        if (entry.mode !== '160000') stack.push(entry.oid);
      }
    } else if (object.kind === 'tag') {
      stack.push(parseTag(object.bytes).object);
    }
  }
  return seen;
}

// ---------------------------------------------------------------------------
// The vault: every repository, issue, pull request and comment, in memory
// ---------------------------------------------------------------------------

interface IssueRec {
  num: number;
  id: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: string[];
  seq: number;
  createdAt: string;
  updatedAt: string;
  closedAt: string | null;
  /** Serialized REST form, rebuilt only when the issue changes. */
  cachedJson: Buffer | null;
}

interface CommentRec {
  id: number;
  body: string;
  createdAt: string;
  updatedAt: string;
}

interface PullRec {
  num: number;
  id: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  merged: boolean;
  mergedAt: string | null;
  mergeSha: string | null;
  headRef: string;
  baseRef: string;
  headSha: string;
  baseSha: string;
  seq: number;
  createdAt: string;
  updatedAt: string;
  closedAt: string | null;
}

interface ForgeRepo {
  id: number;
  name: string;
  owner: string;
  description: string;
  isPrivate: boolean;
  defaultBranch: string;
  seq: number;
  createdAt: string;
  updatedAt: string;
  refs: Map<string, string>;
  objects: Map<string, GitObject>;
  issues: Map<number, IssueRec>;
  pulls: Map<number, PullRec>;
  comments: Map<number, CommentRec[]>;
  labels: Map<string, { name: string; color: string }>;
  nextNumber: number;
  nextCommentId: number;
  /** Bumps on every ref change; git cache keys carry it, so stale packs are impossible. */
  refVer: number;
  /** Cached git wire bytes (advertisements, ls-refs, fetch responses). */
  gitCache: Map<string, Buffer>;
  /** Cached serialized REST form of this repository. */
  repoJsonCache: Buffer | null;
}

/** All repositories, keyed by `owner/name`. */
const vault = new Map<string, ForgeRepo>();
let nextRepoId = 5000;
let nextRecordId = 1;
let nextSeq = 1;

function repoKey(owner: string, name: string): string {
  return `${owner}/${name}`;
}

function lookupRepo(owner: string, name: string): ForgeRepo | undefined {
  return vault.get(repoKey(owner, name));
}

function viewerRepos(): ForgeRepo[] {
  const repos: ForgeRepo[] = [];
  for (const repo of vault.values()) if (repo.owner === VIEWER_LOGIN) repos.push(repo);
  repos.sort((a, b) => a.seq - b.seq);
  return repos;
}

/** Create a repository in the vault, with the six seeded labels and no refs. */
function createForgeRepo(owner: string, name: string, description: string, isPrivate: boolean): ForgeRepo {
  const repo: ForgeRepo = {
    id: nextRepoId,
    name,
    owner,
    description,
    isPrivate,
    defaultBranch: 'main',
    seq: nextSeq,
    createdAt: nowIso(),
    updatedAt: nowIso(),
    refs: new Map(),
    objects: new Map(),
    issues: new Map(),
    pulls: new Map(),
    comments: new Map(),
    labels: new Map(),
    nextNumber: 1,
    nextCommentId: 1,
    refVer: 0,
    gitCache: new Map(),
    repoJsonCache: null,
  };
  nextRepoId += 1;
  nextSeq += 1;
  for (const label of SEED_LABELS) repo.labels.set(label.name, { name: label.name, color: label.color });
  vault.set(repoKey(owner, name), repo);
  return repo;
}

/** Store an object; returns its id. Objects are immutable, so this never invalidates caches. */
function putObject(repo: ForgeRepo, kind: ObjectKind, bytes: Buffer): string {
  const oid = hashObject(kind, bytes);
  if (!repo.objects.has(oid)) repo.objects.set(oid, { kind, bytes });
  return oid;
}

function getObject(repo: ForgeRepo, oid: string): GitObject | undefined {
  return repo.objects.get(oid);
}

/** Move a ref (or create it); bumps the ref version so cached wire bytes go stale. */
function setRef(repo: ForgeRepo, refname: string, oid: string): void {
  repo.refs.set(refname, oid);
  repo.refVer += 1;
  repo.repoJsonCache = null;
}

/** Delete a ref; returns false when it did not exist. */
function deleteRef(repo: ForgeRepo, refname: string): boolean {
  const removed = repo.refs.delete(refname);
  if (removed) {
    repo.refVer += 1;
    repo.repoJsonCache = null;
  }
  return removed;
}

function refTip(repo: ForgeRepo, refname: string): string | undefined {
  return repo.refs.get(refname);
}

function branchRef(branch: string): string {
  return `refs/heads/${branch}`;
}

/** The tip of a branch, or undefined when the branch does not exist. */
function branchTip(repo: ForgeRepo, branch: string): string | undefined {
  return repo.refs.get(branchRef(branch));
}

/** All branch names, in creation order (insertion order of the refs map). */
function branchNames(repo: ForgeRepo): string[] {
  const names: string[] = [];
  for (const refname of repo.refs.keys()) {
    if (refname.startsWith('refs/heads/')) names.push(refname.slice('refs/heads/'.length));
  }
  return names;
}

/** The object kind a ref points at (a tag ref may point at a tag object). */
function refObjectType(repo: ForgeRepo, oid: string): ObjectKind {
  const object = repo.objects.get(oid);
  return object === undefined ? 'commit' : object.kind;
}

// ---------------------------------------------------------------------------
// Global ids (GraphQL): opaque, stable, never a bare database id
// ---------------------------------------------------------------------------

function globalId(kind: string, owner: string, name: string, num: number, extra = ''): string {
  const tail = extra === '' ? `${num}` : `${num}|${extra}`;
  return base64UrlEncode(`${kind}|${owner}/${name}|${tail}`);
}

function userGlobalId(login: string, dbid: number): string {
  return base64UrlEncode(`U|${login}|${dbid}`);
}

interface DecodedGlobalId {
  readonly kind: string;
  readonly owner: string;
  readonly name: string;
  readonly num: number;
  readonly extra: string;
}

function decodeGlobalId(text: string): DecodedGlobalId | null {
  const plain = base64UrlDecode(text);
  if (plain === null) return null;
  const parts = plain.split('|');
  if (parts.length < 3) return null;
  const kind = parts[0] as string;
  const ownerName = parts[1] as string;
  const slash = ownerName.indexOf('/');
  if (slash < 0) return null;
  const owner = ownerName.slice(0, slash);
  const name = ownerName.slice(slash + 1);
  const num = Number.parseInt(parts[2] as string, 10);
  if (!Number.isFinite(num)) return null;
  return { kind, owner, name, num, extra: parts[3] ?? '' };
}

function userIdFromGlobal(text: string): { login: string; dbid: number } | null {
  const plain = base64UrlDecode(text);
  if (plain === null) return null;
  const parts = plain.split('|');
  if (parts.length !== 3 || parts[0] !== 'U') return null;
  const dbid = Number.parseInt(parts[2] as string, 10);
  if (!Number.isFinite(dbid)) return null;
  return { login: parts[1] as string, dbid };
}

// ---------------------------------------------------------------------------
// Tree surgery: read and rebuild nested trees for the contents endpoints
// ---------------------------------------------------------------------------

/** The blob id at `path` in the tree rooted at `treeOid`, or null when absent. */
function treeLookup(repo: ForgeRepo, treeOid: string, path: string): string | null {
  const segments = path.split('/').filter((part) => part.length > 0);
  let current = treeOid;
  for (let index = 0; index < segments.length; index += 1) {
    const object = repo.objects.get(current);
    if (object === undefined || object.kind !== 'tree') return null;
    const entries = parseTree(object.bytes);
    const wanted = segments[index] as string;
    const found = entries.find((entry) => entry.name === wanted);
    if (found === undefined) return null;
    if (index === segments.length - 1) return found.mode === '100644' || found.mode === '100755' ? found.oid : null;
    if (found.mode !== '40000') return null;
    current = found.oid;
  }
  return null;
}

/**
 * Return the tree id that results from setting `path` to `blobOid` (or
 * deleting it when `blobOid` is null) inside the tree rooted at `treeOid`.
 * Intermediate directories are created as needed; emptied ones are pruned.
 */
function treeSetPath(repo: ForgeRepo, treeOid: string, path: string, blobOid: string | null): string {
  const segments = path.split('/').filter((part) => part.length > 0);
  if (segments.length === 0) throw new Error('empty path');
  const rewrite = (currentOid: string, depth: number): string => {
    const object = repo.objects.get(currentOid);
    const entries: TreeEntry[] = object !== undefined && object.kind === 'tree' ? parseTree(object.bytes) : [];
    const wanted = segments[depth] as string;
    const at = entries.findIndex((entry) => entry.name === wanted);
    if (depth === segments.length - 1) {
      if (blobOid === null) {
        if (at >= 0) entries.splice(at, 1);
      } else if (at >= 0) {
        entries[at] = { mode: '100644', name: wanted, oid: blobOid };
      } else {
        entries.push({ mode: '100644', name: wanted, oid: blobOid });
      }
    } else {
      const childOid = at >= 0 && entries[at]?.mode === '40000' ? (entries[at] as TreeEntry).oid : null;
      const base = childOid ?? putObject(repo, 'tree', buildTree([]));
      const rebuilt = rewrite(base, depth + 1);
      const rebuiltEntries = parseTree(repo.objects.get(rebuilt)?.bytes ?? Buffer.alloc(0));
      if (at >= 0) {
        if (rebuiltEntries.length === 0 && blobOid === null) entries.splice(at, 1);
        else entries[at] = { mode: '40000', name: wanted, oid: rebuilt };
      } else if (rebuiltEntries.length > 0) {
        entries.push({ mode: '40000', name: wanted, oid: rebuilt });
      }
    }
    return putObject(repo, 'tree', buildTree(entries));
  };
  return rewrite(treeOid, 0);
}

/** A flat listing of one tree level: files and directories with their modes. */
function treeList(repo: ForgeRepo, treeOid: string): TreeEntry[] {
  const object = repo.objects.get(treeOid);
  if (object === undefined || object.kind !== 'tree') return [];
  return parseTree(object.bytes);
}

/** Walk two trees and list every file that differs (added, removed, modified). */
function treeDiff(
  repo: ForgeRepo,
  baseOid: string,
  headOid: string,
): Array<{ path: string; status: 'added' | 'removed' | 'modified'; baseBlob: string | null; headBlob: string | null }> {
  const baseFiles = new Map<string, string>();
  const headFiles = new Map<string, string>();
  const walk = (treeOid: string, prefix: string, into: Map<string, string>): void => {
    const object = repo.objects.get(treeOid);
    if (object === undefined || object.kind !== 'tree') return;
    for (const entry of parseTree(object.bytes)) {
      const path = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
      if (entry.mode === '40000') walk(entry.oid, path, into);
      else if (entry.mode === '100644' || entry.mode === '100755') into.set(path, entry.oid);
    }
  };
  walk(baseOid, '', baseFiles);
  walk(headOid, '', headFiles);
  const out: Array<{ path: string; status: 'added' | 'removed' | 'modified'; baseBlob: string | null; headBlob: string | null }> = [];
  for (const [path, headBlob] of headFiles) {
    const baseBlob = baseFiles.get(path) ?? null;
    if (baseBlob === null) out.push({ path, status: 'added', baseBlob: null, headBlob });
    else if (baseBlob !== headBlob) out.push({ path, status: 'modified', baseBlob, headBlob });
  }
  for (const [path, baseBlob] of baseFiles) {
    if (!headFiles.has(path)) out.push({ path, status: 'removed', baseBlob, headBlob: null });
  }
  out.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  return out;
}

/** Multiset line diff: lines added and removed between two blob contents. */
function countLineChanges(repo: ForgeRepo, baseBlob: string | null, headBlob: string | null): { additions: number; deletions: number } {
  const linesOf = (oid: string | null): Map<string, number> => {
    const counts = new Map<string, number>();
    if (oid === null) return counts;
    const object = repo.objects.get(oid);
    if (object === undefined || object.kind !== 'blob') return counts;
    const text = object.bytes.toString('utf8');
    const lines = text === '' ? [] : text.split('\n');
    // A trailing newline does not make an extra empty line.
    if (lines.length > 0 && lines[lines.length - 1] === '') lines.pop();
    for (const line of lines) counts.set(line, (counts.get(line) ?? 0) + 1);
    return counts;
  };
  const before = linesOf(baseBlob);
  const after = linesOf(headBlob);
  let additions = 0;
  let deletions = 0;
  for (const [line, count] of after) {
    const prior = before.get(line) ?? 0;
    if (count > prior) additions += count - prior;
  }
  for (const [line, count] of before) {
    const next = after.get(line) ?? 0;
    if (count > next) deletions += count - next;
  }
  return { additions, deletions };
}

/** The merge-base of two commits: the first commit reachable from both (BFS from both tips). */
function mergeBase(repo: ForgeRepo, left: string, right: string): string | null {
  const leftSeen = new Map<string, number>();
  const queue: Array<{ oid: string; depth: number }> = [{ oid: left, depth: 0 }];
  while (queue.length > 0) {
    const current = queue.shift() as { oid: string; depth: number };
    if (leftSeen.has(current.oid)) continue;
    leftSeen.set(current.oid, current.depth);
    const object = repo.objects.get(current.oid);
    if (object === undefined || object.kind !== 'commit') continue;
    for (const parent of parseCommit(object.bytes).parents) {
      queue.push({ oid: parent, depth: current.depth + 1 });
    }
  }
  const rightQueue: string[] = [right];
  const rightSeen = new Set<string>();
  while (rightQueue.length > 0) {
    const oid = rightQueue.shift() as string;
    if (rightSeen.has(oid)) continue;
    rightSeen.add(oid);
    if (leftSeen.has(oid)) return oid;
    const object = repo.objects.get(oid);
    if (object === undefined || object.kind !== 'commit') continue;
    for (const parent of parseCommit(object.bytes).parents) rightQueue.push(parent);
  }
  return null;
}

/** Is `ancestor` reachable from `tip` (following parents)? */
function isAncestor(repo: ForgeRepo, ancestor: string, tip: string): boolean {
  if (ancestor === tip) return true;
  const seen = new Set<string>();
  const stack: string[] = [tip];
  while (stack.length > 0) {
    const oid = stack.pop() as string;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const object = repo.objects.get(oid);
    if (object === undefined || object.kind !== 'commit') continue;
    for (const parent of parseCommit(object.bytes).parents) {
      if (parent === ancestor) return true;
      stack.push(parent);
    }
  }
  return false;
}

/** Commits reachable from `tip`, tip first, parents after, deduplicated. */
function listCommitsFrom(repo: ForgeRepo, tip: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const queue: string[] = [tip];
  while (queue.length > 0) {
    const oid = queue.shift() as string;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const object = repo.objects.get(oid);
    if (object === undefined || object.kind !== 'commit') continue;
    out.push(oid);
    for (const parent of parseCommit(object.bytes).parents) queue.push(parent);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Git wire protocol: advertisements, ls-refs, fetch, receive-pack
// ---------------------------------------------------------------------------

/** Capabilities the forge offers on the upload-pack v2 advertisement. */
function uploadPackCapabilities(): string[] {
  return ['ls-refs=unborn', 'fetch=shallow filter', 'object-format=sha1', `agent=${FORGE_AGENT}`];
}

/** Capabilities the forge offers on the receive-pack v0 advertisement. */
function receivePackCapabilities(): string[] {
  return [
    'report-status',
    'side-band-64k',
    'delete-refs',
    'ofs-delta',
    'symref=HEAD:refs/heads/main',
    `agent=${FORGE_AGENT}`,
  ];
}

/** The v2 advertisement for upload-pack (service preamble + version line + capabilities). */
function advertisementV2(repo: ForgeRepo): Buffer {
  const cacheKey = `adv2:${repo.refVer}`;
  const cached = repo.gitCache.get(cacheKey);
  if (cached !== undefined) return cached;
  const lines: Array<string | 'flush'> = [`# service=git-upload-pack\n`, 'flush', 'version 2\n'];
  for (const capability of uploadPackCapabilities()) lines.push(`${capability}\n`);
  lines.push('flush');
  const bytes = encodePktLines(lines);
  repo.gitCache.set(cacheKey, bytes);
  return bytes;
}

/** The v0 advertisement for a service (service preamble + ref lines, first carrying capabilities). */
function advertisementV0(repo: ForgeRepo, service: 'git-upload-pack' | 'git-receive-pack'): Buffer {
  const cacheKey = `adv0:${repo.refVer}:${service}`;
  const cached = repo.gitCache.get(cacheKey);
  if (cached !== undefined) return cached;
  const capabilities = service === 'git-receive-pack' ? receivePackCapabilities() : [`symref=HEAD:refs/heads/main`, `agent=${FORGE_AGENT}`];
  const lines: Array<string | 'flush'> = [`# service=${service}\n`, 'flush'];
  const refs: Array<{ oid: string; name: string }> = [];
  const headTip = repo.refs.get('refs/heads/main');
  if (headTip !== undefined) refs.push({ oid: headTip, name: 'HEAD' });
  for (const [refname, oid] of repo.refs) refs.push({ oid, name: refname });
  if (refs.length === 0) {
    lines.push(`${ZERO_OID} capabilities^{}\0${capabilities.join(' ')}\n`);
  } else {
    refs.forEach((ref, index) => {
      if (index === 0) lines.push(`${ref.oid} ${ref.name}\0${capabilities.join(' ')}\n`);
      else lines.push(`${ref.oid} ${ref.name}\n`);
      const object = repo.objects.get(ref.oid);
      if (object !== undefined && object.kind === 'tag' && ref.name.startsWith('refs/tags/')) {
        const target = parseTag(object.bytes).object;
        lines.push(`${target} ${ref.name}^{}\n`);
      }
    });
  }
  lines.push('flush');
  const bytes = encodePktLines(lines);
  repo.gitCache.set(cacheKey, bytes);
  return bytes;
}

interface LsRefsOptions {
  readonly prefixes: string[];
  readonly peel: boolean;
  readonly symrefs: boolean;
  readonly unborn: boolean;
}

/** The v2 ls-refs answer: one line per matching ref, with peel/symref attributes. */
function lsRefsV2(repo: ForgeRepo, options: LsRefsOptions): Buffer {
  const cacheKey = `ls:${repo.refVer}:${options.prefixes.join(',')}:${options.peel}:${options.symrefs}:${options.unborn}`;
  const cached = repo.gitCache.get(cacheKey);
  if (cached !== undefined) return cached;
  const keep = (name: string): boolean =>
    options.prefixes.length === 0 || options.prefixes.some((prefix) => name.startsWith(prefix));
  const lines: Array<string | 'flush'> = [];
  const headTip = repo.refs.get('refs/heads/main');
  if (keep('HEAD')) {
    if (headTip !== undefined) {
      lines.push(`${headTip} HEAD${options.symrefs ? ' symref-target:refs/heads/main' : ''}\n`);
    } else if (options.unborn) {
      lines.push(`unborn HEAD${options.symrefs ? ' symref-target:refs/heads/main' : ''}\n`);
    }
  }
  for (const [refname, oid] of repo.refs) {
    if (!keep(refname)) continue;
    let line = `${oid} ${refname}`;
    if (options.peel) {
      const object = repo.objects.get(oid);
      if (object !== undefined && object.kind === 'tag') line += ` peeled:${parseTag(object.bytes).object}`;
    }
    lines.push(`${line}\n`);
  }
  lines.push('flush');
  const bytes = encodePktLines(lines);
  repo.gitCache.set(cacheKey, bytes);
  return bytes;
}

/**
 * The object set a fetch sends: everything reachable from `wants`, minus
 * everything reachable from `haves`, honouring a shallow `depth` when given.
 * Returns the object ids plus the shallow boundary commits for the reply.
 */
function fetchObjectSet(
  repo: ForgeRepo,
  wants: readonly string[],
  haves: readonly string[],
  depth: number | null,
  filter: string | null,
  shallowBoundaries: readonly string[] = [],
): { oids: string[]; shallow: string[] } {
  const lookup = (oid: string): GitObject | undefined => repo.objects.get(oid);
  const haveReachable = collectReachableCut(haves, lookup, new Set(shallowBoundaries));
  const wanted = new Set<string>();
  const shallow: string[] = [];
  if (depth === null) {
    for (const oid of collectReachable(wants, lookup)) wanted.add(oid);
  } else {
    // Breadth-first over commits, tracking distance from the nearest want.
    const distance = new Map<string, number>();
    const queue: string[] = [];
    for (const want of wants) {
      if (!distance.has(want)) {
        distance.set(want, 0);
        queue.push(want);
      }
    }
    while (queue.length > 0) {
      const oid = queue.shift() as string;
      const dist = distance.get(oid) as number;
      const object = repo.objects.get(oid);
      if (object === undefined || object.kind !== 'commit') continue;
      if (dist > depth - 1) continue;
      const view = parseCommit(object.bytes);
      wanted.add(oid);
      wanted.add(view.tree);
      for (const entryOid of collectReachable([view.tree], lookup)) wanted.add(entryOid);
      if (dist === depth - 1) {
        if (view.parents.length > 0) shallow.push(oid);
        continue;
      }
      for (const parent of view.parents) {
        if (!distance.has(parent)) {
          distance.set(parent, dist + 1);
          queue.push(parent);
        }
      }
    }
    // A want that is not a commit (a tag, a tree, a blob) still ships whole.
    for (const want of wants) {
      const object = repo.objects.get(want);
      if (object !== undefined && object.kind !== 'commit') {
        for (const oid of collectReachable([want], lookup)) wanted.add(oid);
      }
    }
  }
  for (const oid of haveReachable) wanted.delete(oid);
  let oids = [...wanted];
  if (filter === 'blob:none') {
    oids = oids.filter((oid) => repo.objects.get(oid)?.kind !== 'blob');
  } else if (filter === 'tree:0') {
    oids = oids.filter((oid) => {
      const kind = repo.objects.get(oid)?.kind;
      return kind !== 'tree' && kind !== 'blob';
    });
  }
  oids.sort();
  return { oids, shallow };
}

/** The v2 fetch reply: acknowledgments, shallow-info, then the sideband packfile. */
function fetchV2Response(
  repo: ForgeRepo,
  wants: readonly string[],
  haves: readonly string[],
  depth: number | null,
  filter: string | null,
  shallowBoundaries: readonly string[],
): Buffer {
  const cacheKey = `fetch:${repo.refVer}:${[...wants].sort().join(',')}:${[...haves].sort().join(',')}:${depth ?? ''}:${filter ?? ''}:${[...shallowBoundaries].sort().join(',')}`;
  const cached = repo.gitCache.get(cacheKey);
  if (cached !== undefined) return cached;
  const { oids, shallow } = fetchObjectSet(repo, wants, haves, depth, filter, shallowBoundaries);
  const sentSet = new Set(oids);
  const unshallow: string[] = [];
  for (const boundary of shallowBoundaries) {
    const object = repo.objects.get(boundary);
    if (object !== undefined && object.kind === 'commit') {
      const parents = parseCommit(object.bytes).parents;
      if (parents.some((parent) => sentSet.has(parent))) unshallow.push(boundary);
    }
  }
  const unshallowSet = new Set(unshallow);
  const stillShallow = shallowBoundaries.filter((boundary) => !unshallowSet.has(boundary));
  const allShallow = [...new Set([...stillShallow, ...shallow])];
  const parts: Buffer[] = [];
  const section = (name: string, lines: string[]): void => {
    parts.push(encodePktLine(`${name}\n`));
    for (const line of lines) parts.push(encodePktLine(`${line}\n`));
    parts.push(DELIM_PACKET);
  };
  const knownHave = haves.find((have) => repo.objects.has(have));
  if (knownHave !== undefined) section('acknowledgments', [`ACK ${knownHave}`, 'ready']);
  else section('acknowledgments', ['NAK']);
  const shallowLines = [
    ...allShallow.map((oid) => `shallow ${oid}`),
    ...unshallow.map((oid) => `unshallow ${oid}`),
  ];
  if (shallowLines.length > 0) section('shallow-info', shallowLines);
  const packObjects: GitObject[] = [];
  for (const oid of oids) {
    const object = repo.objects.get(oid);
    if (object !== undefined) packObjects.push(object);
  }
  const pack = buildPack(packObjects);
  parts.push(encodePktLine('packfile\n'));
  for (let offset = 0; offset < pack.length; offset += SIDEBAND_CHUNK) {
    const chunk = pack.subarray(offset, Math.min(offset + SIDEBAND_CHUNK, pack.length));
    const framed = Buffer.concat([Buffer.from([1]), chunk]);
    parts.push(encodePktLine(framed));
  }
  parts.push(FLUSH_PACKET);
  const bytes = Buffer.concat(parts);
  repo.gitCache.set(cacheKey, bytes);
  return bytes;
}

interface PushCommand {
  readonly oldOid: string;
  readonly newOid: string;
  readonly ref: string;
}

/** Parse the pkt-line command list of a receive-pack request; the pack follows the flush. */
function parsePushCommands(body: Buffer): { commands: PushCommand[]; pack: Buffer } {
  const decoded = decodeUntilFlush(body);
  if (decoded === null) throw new Error('push command list has no flush packet');
  const commands: PushCommand[] = [];
  for (const packet of decoded.packets) {
    if (packet.kind !== 'data') continue;
    let text = packet.payload.toString('utf8');
    const nul = text.indexOf('\0');
    if (nul >= 0) text = text.slice(0, nul);
    const line = text.replace(/\n$/, '');
    if (line === '') continue;
    const parts = line.split(' ');
    if (parts.length < 3) throw new Error(`push command line has too few fields: ${JSON.stringify(line.slice(0, 60))}`);
    const oldOid = parts[0] as string;
    const newOid = parts[1] as string;
    const ref = parts.slice(2).join(' ');
    if (!isHex40(oldOid) || !isHex40(newOid)) throw new Error('push command has a bad object id');
    commands.push({ oldOid, newOid, ref });
  }
  return { commands, pack: body.subarray(decoded.afterFlush) };
}

/** The receive-pack report, framed as pkt-lines inside sideband band 1. */
function pushReportBytes(unpack: string, refs: ReadonlyArray<{ ref: string; ok: boolean; reason: string }>): Buffer {
  const lines: string[] = [`unpack ${unpack}\n`];
  for (const ref of refs) {
    lines.push(ref.ok ? `ok ${ref.ref}\n` : `ng ${ref.ref} ${ref.reason}\n`);
  }
  const inner = encodePktLines(lines);
  const parts: Buffer[] = [];
  for (let offset = 0; offset < inner.length; offset += SIDEBAND_CHUNK) {
    const chunk = inner.subarray(offset, Math.min(offset + SIDEBAND_CHUNK, inner.length));
    parts.push(encodePktLine(Buffer.concat([Buffer.from([1]), chunk])));
  }
  parts.push(FLUSH_PACKET);
  return Buffer.concat(parts);
}

/**
 * Apply a receive-pack: unpack the pack, then apply each ref command.
 * Returns the report bytes. A bad pack fails the unpack and updates no ref.
 */
function applyReceivePack(repo: ForgeRepo, body: Buffer): Buffer {
  let commands: PushCommand[];
  let pack: Buffer;
  try {
    ({ commands, pack } = parsePushCommands(body));
  } catch (error) {
    return pushReportBytes(`error ${(error as Error).message}`, []);
  }
  if (commands.length === 0) return pushReportBytes('ok', []);
  if (pack.length > 0) {
    try {
      const parsed = parsePack(pack, (oid) => repo.objects.get(oid));
      for (const [oid, object] of parsed.objects) {
        if (!repo.objects.has(oid)) repo.objects.set(oid, object);
      }
    } catch (error) {
      const refs = commands.map((command) => ({ ref: command.ref, ok: false, reason: 'unpacker error' }));
      return pushReportBytes(`error ${(error as Error).message}`, refs);
    }
  }
  const results: Array<{ ref: string; ok: boolean; reason: string }> = [];
  for (const command of commands) {
    const current = repo.refs.get(command.ref);
    if (command.newOid === ZERO_OID) {
      // Delete.
      if (current === undefined) {
        results.push({ ref: command.ref, ok: false, reason: 'remote ref does not exist' });
      } else if (current !== command.oldOid && command.oldOid !== ZERO_OID) {
        results.push({ ref: command.ref, ok: false, reason: 'non-fast-forward' });
      } else {
        deleteRef(repo, command.ref);
        results.push({ ref: command.ref, ok: true, reason: '' });
      }
      continue;
    }
    const target = repo.objects.get(command.newOid);
    if (target === undefined) {
      results.push({ ref: command.ref, ok: false, reason: 'object not found' });
      continue;
    }
    if (command.ref.startsWith('refs/heads/')) {
      let commitOid = command.newOid;
      if (target.kind === 'tag') commitOid = parseTag(target.bytes).object;
      const commitObject = repo.objects.get(commitOid);
      if (commitObject === undefined || commitObject.kind !== 'commit') {
        results.push({ ref: command.ref, ok: false, reason: 'object is not a commit' });
        continue;
      }
      if (current === undefined) {
        if (command.oldOid !== ZERO_OID) {
          results.push({ ref: command.ref, ok: false, reason: 'remote ref does not exist' });
          continue;
        }
        setRef(repo, command.ref, command.newOid);
        results.push({ ref: command.ref, ok: true, reason: '' });
        continue;
      }
      if (current !== command.oldOid) {
        results.push({ ref: command.ref, ok: false, reason: 'non-fast-forward' });
        continue;
      }
      if (!isAncestor(repo, current, commitOid)) {
        results.push({ ref: command.ref, ok: false, reason: 'non-fast-forward' });
        continue;
      }
      setRef(repo, command.ref, command.newOid);
      results.push({ ref: command.ref, ok: true, reason: '' });
      continue;
    }
    // Tags and other refs: create, or replace when the old value matches.
    if (current === undefined) {
      if (command.oldOid !== ZERO_OID) {
        results.push({ ref: command.ref, ok: false, reason: 'remote ref does not exist' });
        continue;
      }
      setRef(repo, command.ref, command.newOid);
      results.push({ ref: command.ref, ok: true, reason: '' });
      continue;
    }
    if (current !== command.oldOid) {
      results.push({ ref: command.ref, ok: false, reason: 'non-fast-forward' });
      continue;
    }
    setRef(repo, command.ref, command.newOid);
    results.push({ ref: command.ref, ok: true, reason: '' });
  }
  return pushReportBytes('ok', results);
}

// ---------------------------------------------------------------------------
// REST v3: response envelope, serializers, handlers
// ---------------------------------------------------------------------------

interface ForgeResponse {
  readonly status: number;
  readonly body: Buffer;
  readonly contentType: string;
  readonly headers: Record<string, string>;
}

interface RequestContext {
  readonly method: string;
  readonly segments: string[];
  readonly query: Record<string, string>;
  readonly bodyText: string;
  readonly headers: Record<string, string | string[] | undefined>;
  readonly baseUrl: string;
}

function jsonResponse(status: number, value: unknown, extraHeaders: Record<string, string> = {}): ForgeResponse {
  return {
    status,
    body: Buffer.from(toJson(value), 'utf8'),
    contentType: 'application/json; charset=utf-8',
    headers: extraHeaders,
  };
}

function bufferResponse(status: number, body: Buffer, contentType: string, extraHeaders: Record<string, string> = {}): ForgeResponse {
  return { status, body, contentType, headers: extraHeaders };
}

function errorResponse(status: number, message: string): ForgeResponse {
  return jsonResponse(status, { message });
}

function noContentResponse(): ForgeResponse {
  return { status: 204, body: Buffer.alloc(0), contentType: 'application/json; charset=utf-8', headers: {} };
}

/** Parse the request JSON body; on failure the caller answers 400. */
function requestJson(ctx: RequestContext): { ok: true; value: unknown } | { ok: false } {
  try {
    return { ok: true, value: parseJsonBody(ctx.bodyText) };
  } catch {
    return { ok: false };
  }
}

function userJson(login: string, id: number): Record<string, unknown> {
  const out: Record<string, unknown> = {
    login,
    id,
    node_id: userGlobalId(login, id),
    avatar_url: `https://avatars.githubusercontent.com/u/${id}?v=4`,
    gravatar_id: '',
    url: `https://api.github.com/users/${login}`,
    html_url: `https://github.com/${login}`,
    type: 'User',
    site_admin: false,
  };
  if (login === VIEWER_LOGIN) {
    out.name = VIEWER_NAME;
    out.email = VIEWER_EMAIL;
  }
  return out;
}

function labelJson(repo: ForgeRepo, name: string): Record<string, unknown> | null {
  const label = repo.labels.get(name);
  if (label === undefined) return null;
  const index = SEED_LABELS.findIndex((seed) => seed.name === name);
  return {
    id: index >= 0 ? index + 1 : 1000 + name.length,
    node_id: base64UrlEncode(`L|${repo.owner}/${repo.name}|${name}`),
    url: `https://api.github.com/repos/${repo.owner}/${repo.name}/labels/${encodeURIComponent(name)}`,
    name: label.name,
    color: label.color,
    default: index >= 0,
    description: '',
  };
}

function repoJson(repo: ForgeRepo): Buffer {
  if (repo.repoJsonCache !== null) return repo.repoJsonCache;
  const openCount = [...repo.issues.values()].filter((issue) => issue.state === 'open').length +
    [...repo.pulls.values()].filter((pull) => pull.state === 'open').length;
  const body = toJson({
    id: repo.id,
    node_id: globalId('R', repo.owner, repo.name, repo.id),
    name: repo.name,
    full_name: `${repo.owner}/${repo.name}`,
    owner: userJson(repo.owner, repo.owner === VIEWER_LOGIN ? VIEWER_ID : 0),
    private: repo.isPrivate,
    description: repo.description,
    default_branch: repo.defaultBranch,
    created_at: repo.createdAt,
    updated_at: repo.updatedAt,
    pushed_at: repo.updatedAt,
    html_url: `https://github.com/${repo.owner}/${repo.name}`,
    clone_url: `https://github.com/${repo.owner}/${repo.name}.git`,
    git_url: `git://github.com/${repo.owner}/${repo.name}.git`,
    ssh_url: `git@github.com:${repo.owner}/${repo.name}.git`,
    homepage: null,
    language: null,
    forks_count: 0,
    stargazers_count: 0,
    watchers_count: 0,
    size: 0,
    open_issues_count: openCount,
    has_issues: true,
    has_projects: true,
    has_downloads: true,
    has_wiki: true,
    has_pages: false,
    archived: false,
    disabled: false,
    visibility: repo.isPrivate ? 'private' : 'public',
    license: null,
    topics: [],
    permissions: { admin: true, maintain: true, push: true, triage: true, pull: true },
  });
  const bytes = Buffer.from(body, 'utf8');
  repo.repoJsonCache = bytes;
  return bytes;
}

function issueJson(repo: ForgeRepo, issue: IssueRec): Buffer {
  if (issue.cachedJson !== null) return issue.cachedJson;
  const commentCount = repo.comments.get(issue.num)?.length ?? 0;
  const labels = issue.labels
    .map((name) => labelJson(repo, name))
    .filter((label): label is Record<string, unknown> => label !== null);
  const body = toJson({
    id: issue.id,
    node_id: globalId('I', repo.owner, repo.name, issue.num),
    number: issue.num,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    user: userJson(VIEWER_LOGIN, VIEWER_ID),
    labels,
    assignee: null,
    assignees: [],
    milestone: null,
    locked: false,
    comments: commentCount,
    created_at: issue.createdAt,
    updated_at: issue.updatedAt,
    closed_at: issue.closedAt,
    author_association: 'OWNER',
    html_url: `https://github.com/${repo.owner}/${repo.name}/issues/${issue.num}`,
    url: `https://api.github.com/repos/${repo.owner}/${repo.name}/issues/${issue.num}`,
    repository_url: `https://api.github.com/repos/${repo.owner}/${repo.name}`,
    labels_url: `https://api.github.com/repos/${repo.owner}/${repo.name}/issues/${issue.num}/labels{/name}`,
    comments_url: `https://api.github.com/repos/${repo.owner}/${repo.name}/issues/${issue.num}/comments`,
    events_url: `https://api.github.com/repos/${repo.owner}/${repo.name}/issues/${issue.num}/events`,
  });
  const bytes = Buffer.from(body, 'utf8');
  issue.cachedJson = bytes;
  return bytes;
}

function commentJson(repo: ForgeRepo, issueNum: number, comment: CommentRec): Record<string, unknown> {
  return {
    id: comment.id,
    node_id: globalId('C', repo.owner, repo.name, issueNum, `${comment.id}`),
    body: comment.body,
    user: userJson(VIEWER_LOGIN, VIEWER_ID),
    created_at: comment.createdAt,
    updated_at: comment.updatedAt,
    html_url: `https://github.com/${repo.owner}/${repo.name}/issues/${issueNum}#issuecomment-${comment.id}`,
    url: `https://api.github.com/repos/${repo.owner}/${repo.name}/issues/comments/${comment.id}`,
    issue_url: `https://api.github.com/repos/${repo.owner}/${repo.name}/issues/${issueNum}`,
    author_association: 'OWNER',
  };
}

function parseIdentityLine(line: string): { name: string; email: string; epoch: number } {
  const open = line.indexOf('<');
  const close = line.indexOf('>');
  if (open < 0 || close < 0 || close < open) return { name: line, email: '', epoch: 0 };
  const name = line.slice(0, open).trim();
  const email = line.slice(open + 1, close);
  const rest = line.slice(close + 1).trim().split(/\s+/);
  const epoch = Number.parseInt(rest[0] ?? '0', 10);
  return { name, email, epoch: Number.isFinite(epoch) ? epoch : 0 };
}

function commitJson(repo: ForgeRepo, oid: string): Record<string, unknown> | null {
  const object = repo.objects.get(oid);
  if (object === undefined || object.kind !== 'commit') return null;
  const view = parseCommit(object.bytes);
  const author = parseIdentityLine(view.author);
  const committer = parseIdentityLine(view.committer);
  const authorDate = new Date(author.epoch * 1000).toISOString();
  const committerDate = new Date(committer.epoch * 1000).toISOString();
  return {
    sha: oid,
    node_id: base64UrlEncode(`K|${oid}`),
    commit: {
      message: view.message,
      author: { name: author.name, email: author.email, date: authorDate },
      committer: { name: committer.name, email: committer.email, date: committerDate },
      tree: { sha: view.tree, url: `https://api.github.com/repos/${repo.owner}/${repo.name}/git/trees/${view.tree}` },
      url: `https://api.github.com/repos/${repo.owner}/${repo.name}/git/commits/${oid}`,
      comment_count: 0,
      verification: { verified: false, reason: 'unsigned', signature: null, payload: null },
    },
    parents: view.parents.map((parent) => ({
      sha: parent,
      url: `https://api.github.com/repos/${repo.owner}/${repo.name}/commits/${parent}`,
      html_url: `https://github.com/${repo.owner}/${repo.name}/commit/${parent}`,
    })),
    url: `https://api.github.com/repos/${repo.owner}/${repo.name}/commits/${oid}`,
    html_url: `https://github.com/${repo.owner}/${repo.name}/commit/${oid}`,
    author: userJson(author.name === VIEWER_NAME ? VIEWER_LOGIN : author.name, VIEWER_ID),
    committer: userJson(committer.name === VIEWER_NAME ? VIEWER_LOGIN : committer.name, VIEWER_ID),
  };
}

function pullDiffStats(repo: ForgeRepo, pull: PullRec): { additions: number; deletions: number; changed: number } {
  const baseObject = repo.objects.get(pull.baseSha);
  const headObject = repo.objects.get(pull.headSha);
  if (baseObject === undefined || headObject === undefined) return { additions: 0, deletions: 0, changed: 0 };
  if (baseObject.kind !== 'commit' || headObject.kind !== 'commit') return { additions: 0, deletions: 0, changed: 0 };
  const baseTree = parseCommit(baseObject.bytes).tree;
  const headTree = parseCommit(headObject.bytes).tree;
  const diffs = treeDiff(repo, baseTree, headTree);
  let additions = 0;
  let deletions = 0;
  for (const diff of diffs) {
    const counts = countLineChanges(repo, diff.baseBlob, diff.headBlob);
    additions += counts.additions;
    deletions += counts.deletions;
  }
  return { additions, deletions, changed: diffs.length };
}

function pullJson(repo: ForgeRepo, pull: PullRec): Record<string, unknown> {
  const stats = pullDiffStats(repo, pull);
  return {
    id: pull.id,
    node_id: globalId('P', repo.owner, repo.name, pull.num),
    number: pull.num,
    title: pull.title,
    body: pull.body,
    state: pull.state,
    merged: pull.merged,
    merged_at: pull.mergedAt,
    merge_commit_sha: pull.mergeSha,
    head: {
      label: `${repo.owner}:${pull.headRef}`,
      ref: pull.headRef,
      sha: pull.headSha,
      user: userJson(VIEWER_LOGIN, VIEWER_ID),
      repo: JSON.parse(repoJson(repo).toString('utf8')) as Record<string, unknown>,
    },
    base: {
      label: `${repo.owner}:${pull.baseRef}`,
      ref: pull.baseRef,
      sha: pull.baseSha,
      user: userJson(VIEWER_LOGIN, VIEWER_ID),
      repo: JSON.parse(repoJson(repo).toString('utf8')) as Record<string, unknown>,
    },
    user: userJson(VIEWER_LOGIN, VIEWER_ID),
    created_at: pull.createdAt,
    updated_at: pull.updatedAt,
    closed_at: pull.closedAt,
    html_url: `https://github.com/${repo.owner}/${repo.name}/pull/${pull.num}`,
    url: `https://api.github.com/repos/${repo.owner}/${repo.name}/pulls/${pull.num}`,
    draft: false,
    mergeable: true,
    mergeable_state: 'clean',
    merged_by: null,
    assignee: null,
    assignees: [],
    milestone: null,
    locked: false,
    comments: 0,
    review_comments: 0,
    commits: 1,
    additions: stats.additions,
    deletions: stats.deletions,
    changed_files: stats.changed,
  };
}

/** Slice a list into one page and build the Link header for the next page, if any. */
function paginate<T>(
  items: readonly T[],
  query: Record<string, string>,
  baseUrl: string,
  path: string,
): { page: T[]; link: string | null } {
  const size = pageSize(query);
  const page = pageNumber(query);
  const start = (page - 1) * size;
  const pageItems = items.slice(start, start + size);
  if (start + size >= items.length) return { page: pageItems, link: null };
  const nextQuery: Record<string, string> = { ...query, page: String(page + 1), per_page: String(size) };
  const queryString = Object.entries(nextQuery)
    .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(value)}`)
    .join('&');
  return { page: pageItems, link: `<${baseUrl}${path}?${queryString}>; rel="next"` };
}

/** Resolve `owner/name` from the path; the repository must belong to the viewer. */
function resolveRepo(ctx: RequestContext, ownerIndex: number, nameIndex: number): ForgeRepo | null {
  const owner = decodeSegment(ctx.segments[ownerIndex] ?? '');
  const name = decodeSegment(ctx.segments[nameIndex] ?? '');
  if (owner !== VIEWER_LOGIN) return null;
  return lookupRepo(owner, name) ?? null;
}

function restRoot(ctx: RequestContext): ForgeResponse {
  void ctx;
  return jsonResponse(
    200,
    {
      current_user_url: 'https://api.github.com/user',
      current_user_authorizations_html_url: 'https://github.com/settings/applications',
      authorizations_url: 'https://api.github.com/authorizations',
      code_search_url: 'https://api.github.com/search/code?q={query}{&page,per_page,sort,order}',
      commit_search_url: 'https://api.github.com/search/commits?q={query}{&page,per_page,sort,order}',
      emails_url: 'https://api.github.com/user/emails',
      emojis_url: 'https://api.github.com/emojis',
      events_url: 'https://api.github.com/events',
      feeds_url: 'https://api.github.com/feeds',
      followers_url: 'https://api.github.com/user/followers',
      following_url: 'https://api.github.com/user/following{/target}',
      gists_url: 'https://api.github.com/gists{/gist_id}',
      hub_url: 'https://api.github.com/hub',
      issue_search_url: 'https://api.github.com/search/issues?q={query}{&page,per_page,sort,order}',
      issues_url: 'https://api.github.com/issues',
      keys_url: 'https://api.github.com/user/keys',
      label_search_url: 'https://api.github.com/search/labels?repository_id={repository_id}&q={query}{&page,per_page}',
      notifications_url: 'https://api.github.com/notifications',
      organization_url: 'https://api.github.com/orgs/{org}',
      organization_repositories_url: 'https://api.github.com/orgs/{org}/repos{?type,page,per_page,sort}',
      organization_teams_url: 'https://api.github.com/orgs/{org}/teams',
      public_gists_url: 'https://api.github.com/gists/public',
      rate_limit_url: 'https://api.github.com/rate_limit',
      repository_url: 'https://api.github.com/repos/{owner}/{repo}',
      repository_search_url: 'https://api.github.com/search/repositories?q={query}{&page,per_page,sort,order}',
      current_user_repositories_url: 'https://api.github.com/user/repos{?type,page,per_page,sort}',
      starred_url: 'https://api.github.com/user/starred{/owner}{/repo}',
      starred_gists_url: 'https://api.github.com/gists/starred',
      topic_search_url: 'https://api.github.com/search/topics?q={query}{&page,per_page}',
      user_url: 'https://api.github.com/users/{user}',
      user_organizations_url: 'https://api.github.com/users/{user}/orgs',
      user_repositories_url: 'https://api.github.com/users/{user}/repos{?type,page,per_page,sort}',
      user_search_url: 'https://api.github.com/search/users?q={query}{&page,per_page,sort,order}',
    },
    { 'X-OAuth-Scopes': 'repo, user' },
  );
}

function restMeta(ctx: RequestContext): ForgeResponse {
  void ctx;
  return jsonResponse(200, {
    verifiable_password_authentication: true,
    installed_version: '1.0.0',
    api: ['https://api.github.com'],
    git: ['https://github.com'],
    hooks: ['https://api.github.com'],
    pages: ['https://pages.github.com'],
    importer: ['https://import.github.com'],
    actions: ['https://actions.github.com'],
  });
}

function restGetUser(ctx: RequestContext): ForgeResponse {
  void ctx;
  return jsonResponse(200, {
    ...userJson(VIEWER_LOGIN, VIEWER_ID),
    name: VIEWER_NAME,
    email: VIEWER_EMAIL,
    public_repos: viewerRepos().length,
    public_gists: 0,
    followers: 0,
    following: 0,
    created_at: '2025-01-01T00:00:00Z',
    updated_at: nowIso(),
  });
}

function restListUserRepos(ctx: RequestContext): ForgeResponse {
  const repos = viewerRepos();
  const { page, link } = paginate(repos, ctx.query, ctx.baseUrl, '/api/v3/user/repos');
  const headers: Record<string, string> = {};
  if (link !== null) headers.link = link;
  return jsonResponse(
    200,
    page.map((repo) => JSON.parse(repoJson(repo).toString('utf8')) as Record<string, unknown>),
    headers,
  );
}

function restCreateRepo(ctx: RequestContext): ForgeResponse {
  const parsed = requestJson(ctx);
  if (!parsed.ok) return errorResponse(400, 'Problems parsing JSON');
  if (!isRecord(parsed.value)) return errorResponse(422, 'Invalid request body');
  const name = asString(parsed.value.name, '');
  const description = asString(parsed.value.description, '');
  const isPrivate = parsed.value.private === true;
  if (name === '' || name.length > 100 || !/^[A-Za-z0-9._-]+$/.test(name)) {
    return errorResponse(422, 'Repository name is invalid');
  }
  if (lookupRepo(VIEWER_LOGIN, name) !== undefined) {
    return jsonResponse(422, {
      message: 'Repository creation failed.',
      errors: [{ resource: 'Repository', code: 'custom', field: 'name', message: 'name already exists on this account' }],
    });
  }
  const repo = createForgeRepo(VIEWER_LOGIN, name, description, isPrivate);
  return bufferResponse(201, repoJson(repo), 'application/json; charset=utf-8');
}

function restGetRepo(ctx: RequestContext): ForgeResponse {
  const repo = resolveRepo(ctx, 3, 4);
  if (repo === null) return errorResponse(404, 'Not Found');
  return bufferResponse(200, repoJson(repo), 'application/json; charset=utf-8');
}

function restPatchRepo(ctx: RequestContext): ForgeResponse {
  const repo = resolveRepo(ctx, 3, 4);
  if (repo === null) return errorResponse(404, 'Not Found');
  const parsed = requestJson(ctx);
  if (!parsed.ok) return errorResponse(400, 'Problems parsing JSON');
  if (!isRecord(parsed.value)) return errorResponse(422, 'Invalid request body');
  if (typeof parsed.value.description === 'string') repo.description = parsed.value.description;
  if (typeof parsed.value.private === 'boolean') repo.isPrivate = parsed.value.private;
  if (typeof parsed.value.default_branch === 'string' && parsed.value.default_branch !== '') {
    repo.defaultBranch = parsed.value.default_branch;
  }
  repo.updatedAt = nowIso();
  repo.repoJsonCache = null;
  return bufferResponse(200, repoJson(repo), 'application/json; charset=utf-8');
}

function restDeleteRepo(ctx: RequestContext): ForgeResponse {
  const repo = resolveRepo(ctx, 3, 4);
  if (repo === null) return errorResponse(404, 'Not Found');
  vault.delete(repoKey(repo.owner, repo.name));
  return noContentResponse();
}

function restListBranches(ctx: RequestContext): ForgeResponse {
  const repo = resolveRepo(ctx, 3, 4);
  if (repo === null) return errorResponse(404, 'Not Found');
  const branches = branchNames(repo).map((name) => ({
    name,
    commit: {
      sha: branchTip(repo, name) ?? ZERO_OID,
      url: `https://api.github.com/repos/${repo.owner}/${repo.name}/commits/${branchTip(repo, name) ?? ZERO_OID}`,
    },
    protected: false,
  }));
  return jsonResponse(200, branches);
}

function restListCommits(ctx: RequestContext): ForgeResponse {
  const repo = resolveRepo(ctx, 3, 4);
  if (repo === null) return errorResponse(404, 'Not Found');
  const shaParam = ctx.query.sha;
  let tip: string | undefined;
  if (shaParam !== undefined && shaParam !== '') {
    if (isHex40(shaParam)) tip = shaParam;
    else tip = branchTip(repo, shaParam);
    if (tip === undefined) return errorResponse(404, 'Not Found');
  } else {
    tip = branchTip(repo, repo.defaultBranch);
    if (tip === undefined) return jsonResponse(200, []);
  }
  const oids = listCommitsFrom(repo, tip);
  const { page, link } = paginate(oids, ctx.query, ctx.baseUrl, `/api/v3/repos/${repo.owner}/${repo.name}/commits`);
  const headers: Record<string, string> = {};
  if (link !== null) headers.link = link;
  const items = page
    .map((oid) => commitJson(repo, oid))
    .filter((item): item is Record<string, unknown> => item !== null);
  return jsonResponse(200, items, headers);
}

function restListRefs(ctx: RequestContext): ForgeResponse {
  const repo = resolveRepo(ctx, 3, 4);
  if (repo === null) return errorResponse(404, 'Not Found');
  const refs: Array<Record<string, unknown>> = [];
  for (const [refname, oid] of repo.refs) {
    refs.push({
      ref: refname,
      node_id: base64UrlEncode(`RF|${repo.owner}/${repo.name}|${refname}`),
      url: `https://api.github.com/repos/${repo.owner}/${repo.name}/git/${refname}`,
      object: {
        sha: oid,
        type: refObjectType(repo, oid),
        url: `https://api.github.com/repos/${repo.owner}/${repo.name}/git/${refObjectType(repo, oid)}s/${oid}`,
      },
    });
  }
  return jsonResponse(200, refs);
}

function restGetRef(ctx: RequestContext): ForgeResponse {
  const repo = resolveRepo(ctx, 3, 4);
  if (repo === null) return errorResponse(404, 'Not Found');
  const refname = ctx.segments.slice(7).map(decodeSegment).join('/');
  const oid = repo.refs.get(refname);
  if (oid === undefined) return errorResponse(404, 'Not Found');
  return jsonResponse(200, {
    ref: refname,
    node_id: base64UrlEncode(`RF|${repo.owner}/${repo.name}|${refname}`),
    url: `https://api.github.com/repos/${repo.owner}/${repo.name}/git/${refname}`,
    object: {
      sha: oid,
      type: refObjectType(repo, oid),
      url: `https://api.github.com/repos/${repo.owner}/${repo.name}/git/${refObjectType(repo, oid)}s/${oid}`,
    },
  });
}

function restCreateRef(ctx: RequestContext): ForgeResponse {
  const repo = resolveRepo(ctx, 3, 4);
  if (repo === null) return errorResponse(404, 'Not Found');
  const parsed = requestJson(ctx);
  if (!parsed.ok) return errorResponse(400, 'Problems parsing JSON');
  if (!isRecord(parsed.value)) return errorResponse(422, 'Invalid request body');
  const ref = asString(parsed.value.ref, '');
  const sha = asString(parsed.value.sha, '');
  if (!ref.startsWith('refs/') || ref.length > 200 || !isHex40(sha)) {
    return errorResponse(422, 'Invalid ref or sha');
  }
  if (repo.refs.has(ref)) return errorResponse(422, 'Reference already exists');
  const target = repo.objects.get(sha);
  if (target === undefined) return errorResponse(422, 'Object does not exist');
  if (ref.startsWith('refs/heads/') && target.kind !== 'commit') {
    return errorResponse(422, 'Branch must point at a commit');
  }
  setRef(repo, ref, sha);
  return jsonResponse(201, {
    ref,
    node_id: base64UrlEncode(`RF|${repo.owner}/${repo.name}|${ref}`),
    url: `https://api.github.com/repos/${repo.owner}/${repo.name}/git/${ref}`,
    object: {
      sha,
      type: refObjectType(repo, sha),
      url: `https://api.github.com/repos/${repo.owner}/${repo.name}/git/${refObjectType(repo, sha)}s/${sha}`,
    },
  });
}

// ---------------------------------------------------------------------------
// REST v3: contents, issues, comments, pull requests
// ---------------------------------------------------------------------------

function resolveContentsRef(repo: ForgeRepo, ctx: RequestContext): string | undefined {
  const refParam = ctx.query.ref;
  if (refParam !== undefined && refParam !== '') {
    if (isHex40(refParam)) return refParam;
    return branchTip(repo, refParam);
  }
  return branchTip(repo, repo.defaultBranch);
}

function contentsPath(ctx: RequestContext): string {
  return ctx.segments.slice(6).map(decodeSegment).join('/');
}

function fileContentJson(repo: ForgeRepo, path: string, blobOid: string): Record<string, unknown> {
  const object = repo.objects.get(blobOid);
  const size = object === undefined ? 0 : object.bytes.length;
  const content = object === undefined ? '' : object.bytes.toString('base64');
  return {
    type: 'file',
    encoding: 'base64',
    size,
    name: path.split('/').pop() ?? path,
    path,
    sha: blobOid,
    content,
    url: `https://api.github.com/repos/${repo.owner}/${repo.name}/contents/${path}`,
    html_url: `https://github.com/${repo.owner}/${repo.name}/blob/HEAD/${path}`,
    git_url: `https://api.github.com/repos/${repo.owner}/${repo.name}/git/blobs/${blobOid}`,
    download_url: `https://raw.githubusercontent.com/${repo.owner}/${repo.name}/HEAD/${path}`,
  };
}

function directoryEntryJson(repo: ForgeRepo, path: string, entry: TreeEntry): Record<string, unknown> {
  const isDir = entry.mode === '40000';
  const object = repo.objects.get(entry.oid);
  return {
    type: isDir ? 'dir' : 'file',
    size: isDir ? 0 : (object?.bytes.length ?? 0),
    name: entry.name,
    path,
    sha: entry.oid,
    url: `https://api.github.com/repos/${repo.owner}/${repo.name}/contents/${path}`,
    html_url: `https://github.com/${repo.owner}/${repo.name}/tree/HEAD/${path}`,
    git_url: `https://api.github.com/repos/${repo.owner}/${repo.name}/git/${isDir ? 'trees' : 'blobs'}/${entry.oid}`,
    download_url: isDir ? null : `https://raw.githubusercontent.com/${repo.owner}/${repo.name}/HEAD/${path}`,
  };
}

function restGetContents(ctx: RequestContext): ForgeResponse {
  const repo = resolveRepo(ctx, 3, 4);
  if (repo === null) return errorResponse(404, 'Not Found');
  const path = contentsPath(ctx);
  const tip = resolveContentsRef(repo, ctx);
  if (tip === undefined) return errorResponse(404, 'Not Found');
  const commitObject = repo.objects.get(tip);
  if (commitObject === undefined || commitObject.kind !== 'commit') return errorResponse(404, 'Not Found');
  const rootTree = parseCommit(commitObject.bytes).tree;
  if (path === '') {
    const entries = treeList(repo, rootTree);
    return jsonResponse(200, entries.map((entry) => directoryEntryJson(repo, entry.name, entry)));
  }
  const blobOid = treeLookup(repo, rootTree, path);
  if (blobOid !== null) return jsonResponse(200, fileContentJson(repo, path, blobOid));
  // Maybe a directory: walk to the tree at this path.
  const segments = path.split('/').filter((part) => part.length > 0);
  let current = rootTree;
  let found = true;
  for (const segment of segments) {
    const object = repo.objects.get(current);
    if (object === undefined || object.kind !== 'tree') {
      found = false;
      break;
    }
    const entry = parseTree(object.bytes).find((item) => item.name === segment);
    if (entry === undefined || entry.mode !== '40000') {
      found = false;
      break;
    }
    current = entry.oid;
  }
  if (!found) return errorResponse(404, 'Not Found');
  const entries = treeList(repo, current);
  return jsonResponse(
    200,
    entries.map((entry) => directoryEntryJson(repo, `${path}/${entry.name}`, entry)),
  );
}

function contentsCommitJson(repo: ForgeRepo, oid: string): Record<string, unknown> | null {
  const full = commitJson(repo, oid);
  if (full === null) return null;
  const inner = full.commit as Record<string, unknown>;
  return {
    sha: oid,
    node_id: full.node_id,
    message: inner.message,
    author: inner.author,
    committer: inner.committer,
    parents: full.parents,
    tree: inner.tree,
    url: full.url,
    html_url: full.html_url,
  };
}

function restPutContents(ctx: RequestContext): ForgeResponse {
  const repo = resolveRepo(ctx, 3, 4);
  if (repo === null) return errorResponse(404, 'Not Found');
  const path = contentsPath(ctx);
  if (path === '') return errorResponse(422, 'Path is required');
  const parsed = requestJson(ctx);
  if (!parsed.ok) return errorResponse(400, 'Problems parsing JSON');
  if (!isRecord(parsed.value)) return errorResponse(422, 'Invalid request body');
  const message = asString(parsed.value.message, '');
  const content = asString(parsed.value.content, '');
  const branch = asString(parsed.value.branch, repo.defaultBranch);
  const expectedSha = typeof parsed.value.sha === 'string' ? parsed.value.sha : null;
  if (message === '' || content === '') return errorResponse(422, 'message and content are required');
  const tip = branchTip(repo, branch);
  const parentTree = tip === undefined ? putObject(repo, 'tree', buildTree([])) : parseCommit(repo.objects.get(tip)?.bytes ?? Buffer.alloc(0)).tree;
  const existing = tip === undefined ? null : treeLookup(repo, parentTree, path);
  if (expectedSha !== null) {
    if (existing === null || existing !== expectedSha) return errorResponse(409, 'sha does not match the current file');
  }
  const bytes = Buffer.from(content, 'base64');
  const blobOid = putObject(repo, 'blob', bytes);
  const newTree = treeSetPath(repo, parentTree, path, blobOid);
  const parents = tip === undefined ? [] : [tip];
  const commitOid = putObject(repo, 'commit', buildCommit(newTree, parents, message, nowEpoch()));
  setRef(repo, branchRef(branch), commitOid);
  const commit = contentsCommitJson(repo, commitOid);
  return jsonResponse(existing === null ? 201 : 200, {
    content: fileContentJson(repo, path, blobOid),
    commit,
  });
}

function restDeleteContents(ctx: RequestContext): ForgeResponse {
  const repo = resolveRepo(ctx, 3, 4);
  if (repo === null) return errorResponse(404, 'Not Found');
  const path = contentsPath(ctx);
  if (path === '') return errorResponse(422, 'Path is required');
  const parsed = requestJson(ctx);
  if (!parsed.ok) return errorResponse(400, 'Problems parsing JSON');
  if (!isRecord(parsed.value)) return errorResponse(422, 'Invalid request body');
  const message = asString(parsed.value.message, '');
  const branch = asString(parsed.value.branch, repo.defaultBranch);
  const expectedSha = typeof parsed.value.sha === 'string' ? parsed.value.sha : null;
  if (message === '') return errorResponse(422, 'message is required');
  const tip = branchTip(repo, branch);
  if (tip === undefined) return errorResponse(404, 'Not Found');
  const commitObject = repo.objects.get(tip);
  if (commitObject === undefined || commitObject.kind !== 'commit') return errorResponse(404, 'Not Found');
  const parentTree = parseCommit(commitObject.bytes).tree;
  const existing = treeLookup(repo, parentTree, path);
  if (existing === null) return errorResponse(404, 'Not Found');
  if (expectedSha !== null && existing !== expectedSha) return errorResponse(409, 'sha does not match the current file');
  const newTree = treeSetPath(repo, parentTree, path, null);
  const commitOid = putObject(repo, 'commit', buildCommit(newTree, [tip], message, nowEpoch()));
  setRef(repo, branchRef(branch), commitOid);
  const commit = contentsCommitJson(repo, commitOid);
  return jsonResponse(200, { content: null, commit });
}

function restListLabels(ctx: RequestContext): ForgeResponse {
  const repo = resolveRepo(ctx, 3, 4);
  if (repo === null) return errorResponse(404, 'Not Found');
  const labels = [...repo.labels.keys()]
    .map((name) => labelJson(repo, name))
    .filter((label): label is Record<string, unknown> => label !== null);
  const { page, link } = paginate(labels, ctx.query, ctx.baseUrl, `/api/v3/repos/${repo.owner}/${repo.name}/labels`);
  const headers: Record<string, string> = {};
  if (link !== null) headers.link = link;
  return jsonResponse(200, page, headers);
}

function restCreateLabel(ctx: RequestContext): ForgeResponse {
  const repo = resolveRepo(ctx, 3, 4);
  if (repo === null) return errorResponse(404, 'Not Found');
  const parsed = requestJson(ctx);
  if (!parsed.ok) return errorResponse(400, 'Problems parsing JSON');
  if (!isRecord(parsed.value)) return errorResponse(422, 'Invalid request body');
  const name = asString(parsed.value.name, '');
  const color = asString(parsed.value.color, '');
  if (name === '') return errorResponse(422, 'name is required');
  const existing = repo.labels.get(name);
  if (existing !== undefined) {
    if (color !== '') existing.color = color;
    return jsonResponse(201, labelJson(repo, name));
  }
  repo.labels.set(name, { name, color: color === '' ? 'ededed' : color });
  return jsonResponse(201, labelJson(repo, name));
}

function restGetLabel(ctx: RequestContext): ForgeResponse {
  const repo = resolveRepo(ctx, 3, 4);
  if (repo === null) return errorResponse(404, 'Not Found');
  const name = decodeSegment(ctx.segments[6] ?? '');
  const label = labelJson(repo, name);
  if (label === null) return errorResponse(404, 'Not Found');
  return jsonResponse(200, label);
}

function issueListItems(repo: ForgeRepo): Array<Record<string, unknown>> {
  const items: Array<{ seq: number; json: Record<string, unknown> }> = [];
  for (const issue of repo.issues.values()) {
    items.push({ seq: issue.seq, json: JSON.parse(issueJson(repo, issue).toString('utf8')) as Record<string, unknown> });
  }
  for (const pull of repo.pulls.values()) {
    const asIssue: Record<string, unknown> = {
      id: pull.id,
      node_id: globalId('P', repo.owner, repo.name, pull.num),
      number: pull.num,
      title: pull.title,
      body: pull.body,
      state: pull.state,
      user: userJson(VIEWER_LOGIN, VIEWER_ID),
      labels: [],
      assignee: null,
      assignees: [],
      milestone: null,
      locked: false,
      comments: 0,
      created_at: pull.createdAt,
      updated_at: pull.updatedAt,
      closed_at: pull.closedAt,
      author_association: 'OWNER',
      pull_request: {
        url: `https://api.github.com/repos/${repo.owner}/${repo.name}/pulls/${pull.num}`,
        html_url: `https://github.com/${repo.owner}/${repo.name}/pull/${pull.num}`,
        diff_url: `https://github.com/${repo.owner}/${repo.name}/pull/${pull.num}.diff`,
        patch_url: `https://github.com/${repo.owner}/${repo.name}/pull/${pull.num}.patch`,
        merged_at: pull.mergedAt,
      },
    };
    items.push({ seq: pull.seq, json: asIssue });
  }
  items.sort((a, b) => a.seq - b.seq);
  return items.map((item) => item.json);
}

function restListIssues(ctx: RequestContext): ForgeResponse {
  const repo = resolveRepo(ctx, 3, 4);
  if (repo === null) return errorResponse(404, 'Not Found');
  const state = ctx.query.state ?? 'open';
  let items = issueListItems(repo);
  if (state !== 'all') items = items.filter((item) => item.state === state);
  const sort = ctx.query.sort ?? 'created';
  const direction = ctx.query.direction ?? 'desc';
  if (sort === 'created' && direction !== 'asc') items = [...items].reverse();
  const { page, link } = paginate(items, ctx.query, ctx.baseUrl, `/api/v3/repos/${repo.owner}/${repo.name}/issues`);
  const headers: Record<string, string> = {};
  if (link !== null) headers.link = link;
  return jsonResponse(200, page, headers);
}

function restCreateIssue(ctx: RequestContext): ForgeResponse {
  const repo = resolveRepo(ctx, 3, 4);
  if (repo === null) return errorResponse(404, 'Not Found');
  const parsed = requestJson(ctx);
  if (!parsed.ok) return errorResponse(400, 'Problems parsing JSON');
  if (!isRecord(parsed.value)) return errorResponse(422, 'Invalid request body');
  const title = asString(parsed.value.title, '');
  const body = asString(parsed.value.body, '');
  if (title === '') return errorResponse(422, 'title is required');
  const labels: string[] = [];
  if (Array.isArray(parsed.value.labels)) {
    for (const label of parsed.value.labels) {
      if (typeof label === 'string') {
        if (!repo.labels.has(label)) {
          return jsonResponse(422, {
            message: 'Validation Failed',
            errors: [{ resource: 'Issue', code: 'custom', field: 'labels', message: `unknown label ${label}` }],
          });
        }
        labels.push(label);
      } else if (isRecord(label) && typeof label.name === 'string') {
        if (!repo.labels.has(label.name)) {
          return jsonResponse(422, {
            message: 'Validation Failed',
            errors: [{ resource: 'Issue', code: 'custom', field: 'labels', message: `unknown label ${label.name}` }],
          });
        }
        labels.push(label.name);
      }
    }
  }
  const now = nowIso();
  const issue: IssueRec = {
    num: repo.nextNumber,
    id: nextRecordId,
    title,
    body,
    state: 'open',
    labels,
    seq: nextSeq,
    createdAt: now,
    updatedAt: now,
    closedAt: null,
    cachedJson: null,
  };
  nextRecordId += 1;
  nextSeq += 1;
  repo.nextNumber += 1;
  repo.issues.set(issue.num, issue);
  repo.comments.set(issue.num, []);
  repo.repoJsonCache = null;
  return bufferResponse(201, issueJson(repo, issue), 'application/json; charset=utf-8');
}

function findIssueOrPull(repo: ForgeRepo, num: number): IssueRec | PullRec | null {
  return repo.issues.get(num) ?? repo.pulls.get(num) ?? null;
}

function restGetIssue(ctx: RequestContext): ForgeResponse {
  const repo = resolveRepo(ctx, 3, 4);
  if (repo === null) return errorResponse(404, 'Not Found');
  const num = Number.parseInt(ctx.segments[6] ?? '', 10);
  if (!Number.isFinite(num)) return errorResponse(404, 'Not Found');
  const issue = repo.issues.get(num);
  if (issue !== undefined) return bufferResponse(200, issueJson(repo, issue), 'application/json; charset=utf-8');
  const pull = repo.pulls.get(num);
  if (pull !== undefined) {
    const asIssue = issueListItems(repo).find((item) => item.number === num);
    if (asIssue !== undefined) return jsonResponse(200, asIssue);
  }
  return errorResponse(404, 'Not Found');
}

function restPatchIssue(ctx: RequestContext): ForgeResponse {
  const repo = resolveRepo(ctx, 3, 4);
  if (repo === null) return errorResponse(404, 'Not Found');
  const num = Number.parseInt(ctx.segments[6] ?? '', 10);
  if (!Number.isFinite(num)) return errorResponse(404, 'Not Found');
  const issue = repo.issues.get(num);
  if (issue === undefined) return errorResponse(404, 'Not Found');
  const parsed = requestJson(ctx);
  if (!parsed.ok) return errorResponse(400, 'Problems parsing JSON');
  if (!isRecord(parsed.value)) return errorResponse(422, 'Invalid request body');
  if (typeof parsed.value.title === 'string' && parsed.value.title !== '') issue.title = parsed.value.title;
  if (typeof parsed.value.body === 'string') issue.body = parsed.value.body;
  if (typeof parsed.value.state === 'string') {
    if (parsed.value.state === 'closed') {
      issue.state = 'closed';
      issue.closedAt = nowIso();
    } else if (parsed.value.state === 'open') {
      issue.state = 'open';
      issue.closedAt = null;
    }
  }
  if (Array.isArray(parsed.value.labels)) {
    const labels: string[] = [];
    for (const label of parsed.value.labels) {
      if (typeof label === 'string' && repo.labels.has(label)) labels.push(label);
    }
    issue.labels = labels;
  }
  issue.updatedAt = nowIso();
  issue.cachedJson = null;
  repo.repoJsonCache = null;
  return bufferResponse(200, issueJson(repo, issue), 'application/json; charset=utf-8');
}

function restListComments(ctx: RequestContext): ForgeResponse {
  const repo = resolveRepo(ctx, 3, 4);
  if (repo === null) return errorResponse(404, 'Not Found');
  const num = Number.parseInt(ctx.segments[6] ?? '', 10);
  if (!Number.isFinite(num)) return errorResponse(404, 'Not Found');
  if (findIssueOrPull(repo, num) === null) return errorResponse(404, 'Not Found');
  const comments = repo.comments.get(num) ?? [];
  const { page, link } = paginate(
    comments,
    ctx.query,
    ctx.baseUrl,
    `/api/v3/repos/${repo.owner}/${repo.name}/issues/${num}/comments`,
  );
  const headers: Record<string, string> = {};
  if (link !== null) headers.link = link;
  return jsonResponse(200, page.map((comment) => commentJson(repo, num, comment)), headers);
}

function restCreateComment(ctx: RequestContext): ForgeResponse {
  const repo = resolveRepo(ctx, 3, 4);
  if (repo === null) return errorResponse(404, 'Not Found');
  const num = Number.parseInt(ctx.segments[6] ?? '', 10);
  if (!Number.isFinite(num)) return errorResponse(404, 'Not Found');
  if (findIssueOrPull(repo, num) === null) return errorResponse(404, 'Not Found');
  const parsed = requestJson(ctx);
  if (!parsed.ok) return errorResponse(400, 'Problems parsing JSON');
  if (!isRecord(parsed.value)) return errorResponse(422, 'Invalid request body');
  const body = asString(parsed.value.body, '');
  if (body === '') return errorResponse(422, 'body is required');
  const now = nowIso();
  const comment: CommentRec = { id: nextRecordId, body, createdAt: now, updatedAt: now };
  nextRecordId += 1;
  const list = repo.comments.get(num) ?? [];
  list.push(comment);
  repo.comments.set(num, list);
  const issue = repo.issues.get(num);
  if (issue !== undefined) issue.cachedJson = null;
  return jsonResponse(201, commentJson(repo, num, comment));
}

function restListPulls(ctx: RequestContext): ForgeResponse {
  const repo = resolveRepo(ctx, 3, 4);
  if (repo === null) return errorResponse(404, 'Not Found');
  const state = ctx.query.state ?? 'open';
  let pulls = [...repo.pulls.values()];
  if (state !== 'all') pulls = pulls.filter((pull) => pull.state === state);
  pulls.sort((a, b) => b.seq - a.seq);
  const { page, link } = paginate(pulls, ctx.query, ctx.baseUrl, `/api/v3/repos/${repo.owner}/${repo.name}/pulls`);
  const headers: Record<string, string> = {};
  if (link !== null) headers.link = link;
  return jsonResponse(200, page.map((pull) => pullJson(repo, pull)), headers);
}

function restCreatePull(ctx: RequestContext): ForgeResponse {
  const repo = resolveRepo(ctx, 3, 4);
  if (repo === null) return errorResponse(404, 'Not Found');
  const parsed = requestJson(ctx);
  if (!parsed.ok) return errorResponse(400, 'Problems parsing JSON');
  if (!isRecord(parsed.value)) return errorResponse(422, 'Invalid request body');
  const title = asString(parsed.value.title, '');
  const body = asString(parsed.value.body, '');
  const head = asString(parsed.value.head, '');
  const base = asString(parsed.value.base, repo.defaultBranch);
  if (title === '' || head === '') return errorResponse(422, 'title and head are required');
  const headSha = branchTip(repo, head);
  const baseSha = branchTip(repo, base);
  if (headSha === undefined) return errorResponse(422, 'Invalid head branch');
  if (baseSha === undefined) return errorResponse(422, 'Invalid base branch');
  if (headSha === baseSha) return errorResponse(422, 'No commits between head and base');
  const now = nowIso();
  const pull: PullRec = {
    num: repo.nextNumber,
    id: nextRecordId,
    title,
    body,
    state: 'open',
    merged: false,
    mergedAt: null,
    mergeSha: null,
    headRef: head,
    baseRef: base,
    headSha,
    baseSha,
    seq: nextSeq,
    createdAt: now,
    updatedAt: now,
    closedAt: null,
  };
  nextRecordId += 1;
  nextSeq += 1;
  repo.nextNumber += 1;
  repo.pulls.set(pull.num, pull);
  repo.comments.set(pull.num, []);
  repo.repoJsonCache = null;
  return jsonResponse(201, pullJson(repo, pull));
}

function restGetPull(ctx: RequestContext): ForgeResponse {
  const repo = resolveRepo(ctx, 3, 4);
  if (repo === null) return errorResponse(404, 'Not Found');
  const num = Number.parseInt(ctx.segments[6] ?? '', 10);
  if (!Number.isFinite(num)) return errorResponse(404, 'Not Found');
  const pull = repo.pulls.get(num);
  if (pull === undefined) return errorResponse(404, 'Not Found');
  return jsonResponse(200, pullJson(repo, pull));
}

function restListPullFiles(ctx: RequestContext): ForgeResponse {
  const repo = resolveRepo(ctx, 3, 4);
  if (repo === null) return errorResponse(404, 'Not Found');
  const num = Number.parseInt(ctx.segments[6] ?? '', 10);
  if (!Number.isFinite(num)) return errorResponse(404, 'Not Found');
  const pull = repo.pulls.get(num);
  if (pull === undefined) return errorResponse(404, 'Not Found');
  const baseObject = repo.objects.get(pull.baseSha);
  const headObject = repo.objects.get(pull.headSha);
  if (baseObject === undefined || headObject === undefined) return jsonResponse(200, []);
  if (baseObject.kind !== 'commit' || headObject.kind !== 'commit') return jsonResponse(200, []);
  const baseTree = parseCommit(baseObject.bytes).tree;
  const headTree = parseCommit(headObject.bytes).tree;
  const diffs = treeDiff(repo, baseTree, headTree);
  const files = diffs.map((diff) => {
    const counts = countLineChanges(repo, diff.baseBlob, diff.headBlob);
    return {
      sha: diff.headBlob ?? diff.baseBlob ?? ZERO_OID,
      filename: diff.path,
      status: diff.status,
      additions: counts.additions,
      deletions: counts.deletions,
      changes: counts.additions + counts.deletions,
      blob_url: `https://github.com/${repo.owner}/${repo.name}/blob/${pull.headSha}/${diff.path}`,
      raw_url: `https://github.com/${repo.owner}/${repo.name}/raw/${pull.headSha}/${diff.path}`,
      contents_url: `https://api.github.com/repos/${repo.owner}/${repo.name}/contents/${diff.path}?ref=${pull.headSha}`,
      patch: '',
    };
  });
  return jsonResponse(200, files);
}

/**
 * Merge a pull request (squash by default): overlay the head's changes since
 * the merge-base onto the base tip. A file changed differently on both sides
 * is a conflict (405). The merge commit has one parent for squash, two for
 * a merge commit.
 */
function restMergePull(ctx: RequestContext): ForgeResponse {
  const repo = resolveRepo(ctx, 3, 4);
  if (repo === null) return errorResponse(404, 'Not Found');
  const num = Number.parseInt(ctx.segments[6] ?? '', 10);
  if (!Number.isFinite(num)) return errorResponse(404, 'Not Found');
  const pull = repo.pulls.get(num);
  if (pull === undefined) return errorResponse(404, 'Not Found');
  if (pull.merged) return errorResponse(405, 'Pull Request is already merged');
  const parsed = requestJson(ctx);
  if (!parsed.ok) return errorResponse(400, 'Problems parsing JSON');
  const body = isRecord(parsed.value) ? parsed.value : {};
  const method = asString(body.merge_method, 'squash');
  const customMessage = typeof body.merge_commit_message === 'string' ? body.merge_commit_message : null;
  const baseObject = repo.objects.get(pull.baseSha);
  const headObject = repo.objects.get(pull.headSha);
  if (baseObject === undefined || headObject === undefined) return errorResponse(405, 'Pull request is not mergeable');
  if (baseObject.kind !== 'commit' || headObject.kind !== 'commit') return errorResponse(405, 'Pull request is not mergeable');
  const baseTip = branchTip(repo, pull.baseRef);
  if (baseTip === undefined || baseTip !== pull.baseSha) {
    // The base moved since the pull was opened: re-read its tip.
    const currentBase = baseTip ?? pull.baseSha;
    const currentBaseObject = repo.objects.get(currentBase);
    if (currentBaseObject === undefined || currentBaseObject.kind !== 'commit') {
      return errorResponse(405, 'Pull request is not mergeable');
    }
    pull.baseSha = currentBase;
  }
  if (pull.baseSha === pull.headSha) return errorResponse(405, 'No commits between head and base');
  const base = mergeBase(repo, pull.baseSha, pull.headSha);
  if (base === null) return errorResponse(405, 'Pull request is not mergeable');
  const baseCommit = repo.objects.get(base);
  const headCommit = repo.objects.get(pull.headSha);
  const tipCommit = repo.objects.get(pull.baseSha);
  if (baseCommit === undefined || headCommit === undefined || tipCommit === undefined) {
    return errorResponse(405, 'Pull request is not mergeable');
  }
  const baseTree = parseCommit(baseCommit.bytes).tree;
  const headTree = parseCommit(headCommit.bytes).tree;
  const tipTree = parseCommit(tipCommit.bytes).tree;
  const headChanges = treeDiff(repo, baseTree, headTree);
  const baseChanges = treeDiff(repo, baseTree, tipTree);
  const baseChanged = new Map<string, { headBlob: string | null }>();
  for (const change of baseChanges) baseChanged.set(change.path, { headBlob: change.headBlob });
  for (const change of headChanges) {
    const other = baseChanged.get(change.path);
    if (other !== undefined && other.headBlob !== change.headBlob) {
      return errorResponse(405, 'Merge conflict');
    }
  }
  let mergedTree = tipTree;
  for (const change of headChanges) {
    mergedTree = treeSetPath(repo, mergedTree, change.path, change.headBlob);
  }
  const message = customMessage ?? `Merge pull request #${num} from ${repo.owner}:${pull.headRef}`;
  const parents = method === 'merge' ? [pull.baseSha, pull.headSha] : [pull.baseSha];
  const commitOid = putObject(repo, 'commit', buildCommit(mergedTree, parents, message, nowEpoch()));
  setRef(repo, branchRef(pull.baseRef), commitOid);
  const now = nowIso();
  pull.merged = true;
  pull.mergedAt = now;
  pull.mergeSha = commitOid;
  pull.state = 'closed';
  pull.closedAt = now;
  pull.updatedAt = now;
  repo.repoJsonCache = null;
  return jsonResponse(200, { merged: true, sha: commitOid, message });
}

// ---------------------------------------------------------------------------
// GraphQL v4: a fixed-document parser and dispatcher over the same store
// ---------------------------------------------------------------------------

type GqlValue =
  | { readonly kind: 'string'; readonly value: string }
  | { readonly kind: 'int'; readonly value: number }
  | { readonly kind: 'float'; readonly value: number }
  | { readonly kind: 'boolean'; readonly value: boolean }
  | { readonly kind: 'null' }
  | { readonly kind: 'enum'; readonly value: string }
  | { readonly kind: 'variable'; readonly name: string }
  | { readonly kind: 'list'; readonly items: readonly GqlValue[] }
  | { readonly kind: 'object'; readonly fields: ReadonlyMap<string, GqlValue> };

interface GqlField {
  readonly alias: string | null;
  readonly name: string;
  readonly args: ReadonlyMap<string, GqlValue>;
  readonly selections: readonly GqlSelection[] | null;
}

type GqlSelection =
  | { readonly kind: 'field'; readonly field: GqlField }
  | { readonly kind: 'fragment'; readonly name: string }
  | { readonly kind: 'inline'; readonly typeCondition: string | null; readonly selections: readonly GqlSelection[] };

interface GqlOperation {
  readonly operation: 'query' | 'mutation';
  readonly name: string | null;
  readonly variables: ReadonlyMap<string, { readonly type: string; readonly defaultValue: GqlValue | null }>;
  readonly selections: readonly GqlSelection[];
}

interface GqlDocument {
  readonly operations: readonly GqlOperation[];
  readonly fragments: ReadonlyMap<string, { readonly typeCondition: string; readonly selections: readonly GqlSelection[] }>;
}

type GqlTokenKind = 'name' | 'int' | 'float' | 'string' | 'punct' | 'spread' | 'eof';

interface GqlToken {
  readonly kind: GqlTokenKind;
  readonly value: string;
}

/** Tokenize a GraphQL document. Commas are insignificant whitespace; `#` starts a comment. */
function tokenizeGraphQL(source: string): GqlToken[] {
  const tokens: GqlToken[] = [];
  let at = 0;
  const isNameStart = (ch: string): boolean => /[A-Za-z_]/.test(ch);
  const isNameChar = (ch: string): boolean => /[A-Za-z0-9_]/.test(ch);
  while (at < source.length) {
    const ch = source[at] as string;
    if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r' || ch === ',') {
      at += 1;
      continue;
    }
    if (ch === '#') {
      while (at < source.length && source[at] !== '\n') at += 1;
      continue;
    }
    if (ch === '.' && source.slice(at, at + 3) === '...') {
      tokens.push({ kind: 'spread', value: '...' });
      at += 3;
      continue;
    }
    if ('{}()[]:!=$@&|'.includes(ch)) {
      tokens.push({ kind: 'punct', value: ch });
      at += 1;
      continue;
    }
    if (ch === '"') {
      let out = '';
      at += 1;
      while (at < source.length) {
        const c = source[at] as string;
        if (c === '"') {
          at += 1;
          break;
        }
        if (c === '\\' && at + 1 < source.length) {
          const esc = source[at + 1] as string;
          if (esc === 'u' && at + 5 < source.length) {
            out += String.fromCharCode(Number.parseInt(source.slice(at + 2, at + 6), 16));
            at += 6;
            continue;
          }
          const simple: Record<string, string> = { '"': '"', '\\': '\\', '/': '/', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' };
          out += simple[esc] ?? esc;
          at += 2;
          continue;
        }
        out += c;
        at += 1;
      }
      tokens.push({ kind: 'string', value: out });
      continue;
    }
    if (ch === '-' || /[0-9]/.test(ch)) {
      let end = at;
      if (source[end] === '-') end += 1;
      while (end < source.length && /[0-9]/.test(source[end] as string)) end += 1;
      let isFloat = false;
      if (source[end] === '.' && /[0-9]/.test(source[end + 1] ?? '')) {
        isFloat = true;
        end += 1;
        while (end < source.length && /[0-9]/.test(source[end] as string)) end += 1;
      }
      if (source[end] === 'e' || source[end] === 'E') {
        isFloat = true;
        end += 1;
        if (source[end] === '+' || source[end] === '-') end += 1;
        while (end < source.length && /[0-9]/.test(source[end] as string)) end += 1;
      }
      tokens.push({ kind: isFloat ? 'float' : 'int', value: source.slice(at, end) });
      at = end;
      continue;
    }
    if (isNameStart(ch)) {
      let end = at;
      while (end < source.length && isNameChar(source[end] as string)) end += 1;
      tokens.push({ kind: 'name', value: source.slice(at, end) });
      at = end;
      continue;
    }
    throw new Error(`unexpected character ${JSON.stringify(ch)} in GraphQL document`);
  }
  tokens.push({ kind: 'eof', value: '' });
  return tokens;
}

class GqlParser {
  private at = 0;
  private readonly tokens: readonly GqlToken[];

  constructor(tokens: readonly GqlToken[]) {
    this.tokens = tokens;
  }

  private peek(): GqlToken {
    return this.tokens[this.at] as GqlToken;
  }

  private next(): GqlToken {
    const token = this.tokens[this.at] as GqlToken;
    if (this.at < this.tokens.length - 1) this.at += 1;
    return token;
  }

  private expectPunct(value: string): void {
    const token = this.next();
    if (token.kind !== 'punct' || token.value !== value) {
      throw new Error(`expected ${JSON.stringify(value)} in GraphQL document, got ${token.value}`);
    }
  }

  private expectName(value?: string): string {
    const token = this.next();
    if (token.kind !== 'name') throw new Error(`expected a name in GraphQL document, got ${token.value}`);
    if (value !== undefined && token.value !== value) throw new Error(`expected ${value} in GraphQL document, got ${token.value}`);
    return token.value;
  }

  parseDocument(): GqlDocument {
    const operations: GqlOperation[] = [];
    const fragments = new Map<string, { typeCondition: string; selections: GqlSelection[] }>();
    while (this.peek().kind !== 'eof') {
      const token = this.peek();
      if (token.kind === 'punct' && token.value === '{') {
        operations.push({
          operation: 'query',
          name: null,
          variables: new Map(),
          selections: this.parseSelectionSet(),
        });
        continue;
      }
      if (token.kind === 'name' && (token.value === 'query' || token.value === 'mutation')) {
        const operation = this.next().value as 'query' | 'mutation';
        let name: string | null = null;
        if (this.peek().kind === 'name') name = this.next().value;
        let variables = new Map<string, { type: string; defaultValue: GqlValue | null }>();
        if (this.peek().kind === 'punct' && this.peek().value === '(') {
          variables = this.parseVariableDefinitions();
        }
        this.skipDirectives();
        operations.push({ operation, name, variables, selections: this.parseSelectionSet() });
        continue;
      }
      if (token.kind === 'name' && token.value === 'fragment') {
        this.next();
        const name = this.expectName();
        this.expectName('on');
        const typeCondition = this.expectName();
        this.skipDirectives();
        fragments.set(name, { typeCondition, selections: this.parseSelectionSet() });
        continue;
      }
      throw new Error(`unexpected token ${token.value} in GraphQL document`);
    }
    return { operations, fragments };
  }

  private parseVariableDefinitions(): Map<string, { type: string; defaultValue: GqlValue | null }> {
    const variables = new Map<string, { type: string; defaultValue: GqlValue | null }>();
    this.expectPunct('(');
    while (!(this.peek().kind === 'punct' && this.peek().value === ')')) {
      this.expectPunct('$');
      const name = this.expectName();
      this.expectPunct(':');
      const type = this.parseTypeName();
      let defaultValue: GqlValue | null = null;
      if (this.peek().kind === 'punct' && this.peek().value === '=') {
        this.next();
        defaultValue = this.parseValueLiteral();
      }
      variables.set(name, { type, defaultValue });
    }
    this.expectPunct(')');
    return variables;
  }

  private parseTypeName(): string {
    let type = '';
    if (this.peek().kind === 'punct' && this.peek().value === '[') {
      this.next();
      type = `[${this.parseTypeName()}]`;
    } else {
      type = this.expectName();
    }
    while (this.peek().kind === 'punct' && this.peek().value === '!') {
      this.next();
      type += '!';
    }
    return type;
  }

  /** Directives are parsed and ignored: the suite's documents do not use them. */
  private skipDirectives(): void {
    while (this.peek().kind === 'punct' && this.peek().value === '@') {
      this.next();
      this.expectName();
      if (this.peek().kind === 'punct' && this.peek().value === '(') this.parseArguments();
    }
  }

  private parseSelectionSet(): GqlSelection[] {
    this.expectPunct('{');
    const selections: GqlSelection[] = [];
    while (!(this.peek().kind === 'punct' && this.peek().value === '}')) {
      if (this.peek().kind === 'eof') throw new Error('unterminated selection set');
      selections.push(this.parseSelection());
    }
    this.expectPunct('}');
    return selections;
  }

  private parseSelection(): GqlSelection {
    if (this.peek().kind === 'spread') {
      this.next();
      if (this.peek().kind === 'name' && this.peek().value === 'on') {
        this.next();
        const typeCondition = this.expectName();
        this.skipDirectives();
        return { kind: 'inline', typeCondition, selections: this.parseSelectionSet() };
      }
      if (this.peek().kind === 'name') {
        const name = this.next().value;
        this.skipDirectives();
        return { kind: 'fragment', name };
      }
      this.skipDirectives();
      return { kind: 'inline', typeCondition: null, selections: this.parseSelectionSet() };
    }
    const first = this.expectName();
    let alias: string | null = null;
    let name = first;
    if (this.peek().kind === 'punct' && this.peek().value === ':') {
      this.next();
      alias = first;
      name = this.expectName();
    }
    let args = new Map<string, GqlValue>();
    if (this.peek().kind === 'punct' && this.peek().value === '(') args = this.parseArguments();
    this.skipDirectives();
    let selections: GqlSelection[] | null = null;
    if (this.peek().kind === 'punct' && this.peek().value === '{') selections = this.parseSelectionSet();
    return { kind: 'field', field: { alias, name, args, selections } };
  }

  private parseArguments(): Map<string, GqlValue> {
    const args = new Map<string, GqlValue>();
    this.expectPunct('(');
    while (!(this.peek().kind === 'punct' && this.peek().value === ')')) {
      const name = this.expectName();
      this.expectPunct(':');
      args.set(name, this.parseValueLiteral());
    }
    this.expectPunct(')');
    return args;
  }

  private parseValueLiteral(): GqlValue {
    const token = this.next();
    if (token.kind === 'string') return { kind: 'string', value: token.value };
    if (token.kind === 'int') return { kind: 'int', value: Number.parseInt(token.value, 10) };
    if (token.kind === 'float') return { kind: 'float', value: Number.parseFloat(token.value) };
    if (token.kind === 'punct' && token.value === '$') return { kind: 'variable', name: this.expectName() };
    if (token.kind === 'punct' && token.value === '[') {
      const items: GqlValue[] = [];
      while (!(this.peek().kind === 'punct' && this.peek().value === ']')) items.push(this.parseValueLiteral());
      this.expectPunct(']');
      return { kind: 'list', items };
    }
    if (token.kind === 'punct' && token.value === '{') {
      const fields = new Map<string, GqlValue>();
      while (!(this.peek().kind === 'punct' && this.peek().value === '}')) {
        const name = this.expectName();
        this.expectPunct(':');
        fields.set(name, this.parseValueLiteral());
      }
      this.expectPunct('}');
      return { kind: 'object', fields };
    }
    if (token.kind === 'name') {
      if (token.value === 'true') return { kind: 'boolean', value: true };
      if (token.value === 'false') return { kind: 'boolean', value: false };
      if (token.value === 'null') return { kind: 'null' };
      return { kind: 'enum', value: token.value };
    }
    throw new Error(`unexpected value token ${token.value} in GraphQL document`);
  }
}

// ---------------------------------------------------------------------------
// GraphQL executor
// ---------------------------------------------------------------------------

type GqlParent = Record<string, unknown> & { __typename?: string };

function gqlResolveValue(value: GqlValue, variables: ReadonlyMap<string, unknown>): unknown {
  switch (value.kind) {
    case 'string':
      return value.value;
    case 'int':
    case 'float':
      return value.value;
    case 'boolean':
      return value.value;
    case 'null':
      return null;
    case 'enum':
      return value.value;
    case 'variable':
      return variables.get(value.name) ?? null;
    case 'list':
      return value.items.map((item) => gqlResolveValue(item, variables));
    case 'object': {
      const out: Record<string, unknown> = {};
      for (const [key, item] of value.fields) out[key] = gqlResolveValue(item, variables);
      return out;
    }
  }
}

function gqlResolveArgs(args: ReadonlyMap<string, GqlValue>, variables: ReadonlyMap<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of args) out[key] = gqlResolveValue(value, variables);
  return out;
}

function cursorForSeq(seq: number): string {
  return base64UrlEncode(`cursor:${seq}`);
}

function seqFromCursor(cursor: unknown): number | null {
  if (typeof cursor !== 'string') return null;
  const plain = base64UrlDecode(cursor);
  if (plain === null || !plain.startsWith('cursor:')) return null;
  const seq = Number.parseInt(plain.slice('cursor:'.length), 10);
  return Number.isFinite(seq) ? seq : null;
}

function fileCursorForIndex(index: number): string {
  return base64UrlEncode(`file:${index}`);
}

function indexFromCursor(cursor: unknown): number | null {
  if (typeof cursor !== 'string') return null;
  const plain = base64UrlDecode(cursor);
  if (plain === null || !plain.startsWith('file:')) return null;
  const index = Number.parseInt(plain.slice('file:'.length), 10);
  return Number.isFinite(index) ? index : null;
}

interface GqlConnection<T> {
  readonly __typename: string;
  readonly nodes: T[];
  readonly totalCount: number;
  readonly pageInfo: {
    readonly __typename: 'PageInfo';
    readonly hasNextPage: boolean;
    readonly hasPreviousPage: boolean;
    readonly startCursor: string | null;
    readonly endCursor: string | null;
  };
}

function makeConnection<T>(
  typename: string,
  all: readonly T[],
  first: number | null,
  after: string | null,
  cursorOf: (item: T, index: number) => string,
  startIndexOf: (cursor: string) => number,
): GqlConnection<T> {
  let start = 0;
  if (after !== null) {
    const index = startIndexOf(after);
    if (index >= 0) start = index + 1;
  }
  const size = first === null || first < 0 ? all.length : first;
  const page = all.slice(start, start + size);
  const endCursor = page.length > 0 ? cursorOf(page[page.length - 1] as T, start + page.length - 1) : null;
  const startCursor = page.length > 0 ? cursorOf(page[0] as T, start) : null;
  return {
    __typename: typename,
    nodes: [...page],
    totalCount: all.length,
    pageInfo: {
      __typename: 'PageInfo',
      hasNextPage: start + page.length < all.length,
      hasPreviousPage: start > 0,
      startCursor,
      endCursor,
    },
  };
}

function repoObject(repo: ForgeRepo): GqlParent {
  return { __typename: 'Repository', _repo: repo };
}

function issueObject(repo: ForgeRepo, issue: IssueRec): GqlParent {
  return { __typename: 'Issue', _repo: repo, _issue: issue };
}

function pullObject(repo: ForgeRepo, pull: PullRec): GqlParent {
  return { __typename: 'PullRequest', _repo: repo, _pull: pull };
}

function userObject(login: string, id: number): GqlParent {
  const out: GqlParent = { __typename: 'User', login, id };
  if (login === VIEWER_LOGIN) {
    out.name = VIEWER_NAME;
    out.email = VIEWER_EMAIL;
  }
  return out;
}

function commentObject(repo: ForgeRepo, num: number, comment: CommentRec): GqlParent {
  return { __typename: 'Comment', _repo: repo, _num: num, _comment: comment };
}

function resolveGlobalNode(id: unknown): GqlParent | null {
  if (typeof id !== 'string') return null;
  const user = userIdFromGlobal(id);
  if (user !== null) return userObject(user.login, user.dbid);
  const decoded = decodeGlobalId(id);
  if (decoded === null) return null;
  const repo = lookupRepo(decoded.owner, decoded.name);
  if (repo === undefined) return null;
  if (decoded.kind === 'R') return repoObject(repo);
  if (decoded.kind === 'I') {
    const issue = repo.issues.get(decoded.num);
    return issue === undefined ? null : issueObject(repo, issue);
  }
  if (decoded.kind === 'P') {
    const pull = repo.pulls.get(decoded.num);
    return pull === undefined ? null : pullObject(repo, pull);
  }
  if (decoded.kind === 'C') {
    const commentId = Number.parseInt(decoded.extra, 10);
    const comments = repo.comments.get(decoded.num) ?? [];
    const comment = comments.find((item) => item.id === commentId);
    return comment === undefined ? null : commentObject(repo, decoded.num, comment);
  }
  return null;
}

const INTROSPECTION_FIELDS: Record<string, string[]> = {
  Issue: ['id', 'number', 'title', 'state', 'body', 'createdAt', 'updatedAt', 'closedAt', 'author', 'labels', 'comments', 'repository'],
  PullRequest: ['id', 'number', 'title', 'state', 'body', 'merged', 'mergeable', 'headRefName', 'baseRefName', 'headRefOid', 'baseRefOid', 'files', 'author', 'createdAt', 'updatedAt', 'closedAt', 'mergedAt', 'repository'],
  Repository: ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequest', 'pullRequests', 'url'],
  User: ['id', 'login', 'name', 'email', 'databaseId'],
  SearchType: [],
};

function introspectionType(name: unknown): GqlParent | null {
  if (typeof name !== 'string') return null;
  if (name === 'SearchType') {
    return {
      __typename: '__Type',
      name: 'SearchType',
      kind: 'ENUM',
      fields: null,
      enumValues: ['ISSUE', 'REPOSITORY', 'USER', 'DISCUSSION', 'COMMIT', 'CODE', 'MILESTONE'].map((value) => ({
        __typename: '__EnumValue',
        name: value,
        description: null,
      })),
    };
  }
  if (name === 'MergeableState') {
    return {
      __typename: '__Type',
      name: 'MergeableState',
      kind: 'ENUM',
      fields: null,
      enumValues: ['MERGEABLE', 'CONFLICTING', 'UNKNOWN'].map((value) => ({
        __typename: '__EnumValue',
        name: value,
        description: null,
      })),
    };
  }
  const fields = INTROSPECTION_FIELDS[name];
  if (fields === undefined) return null;
  return {
    __typename: '__Type',
    name,
    kind: 'OBJECT',
    fields: fields.map((field) => ({ __typename: '__Field', name: field, description: null, args: [], type: null })),
    enumValues: null,
  };
}

type GqlResolver = (parent: GqlParent, args: Record<string, unknown>) => unknown;

const FIELD_TYPES: Record<string, Record<string, string>> = {
  Query: { viewer: 'User', repository: 'Repository', node: 'Node', __type: '__Type', __schema: '__Schema' },
  Mutation: { createIssue: 'CreateIssuePayload', closeIssue: 'CloseIssuePayload', createPullRequest: 'CreatePullRequestPayload', mergePullRequest: 'MergePullRequestPayload', addComment: 'AddCommentPayload' },
  User: { login: 'String', id: 'ID', name: 'String', email: 'String', databaseId: 'Int' },
  Repository: {
    id: 'ID', databaseId: 'Int', name: 'String', nameWithOwner: 'String', owner: 'User',
    defaultBranchRef: 'BranchRef', viewerPermission: 'String', hasIssuesEnabled: 'Boolean',
    issue: 'Issue', issues: 'IssueConnection', pullRequest: 'PullRequest', pullRequests: 'PullRequestConnection',
    url: 'String', html_url: 'String',
  },
  Issue: {
    id: 'ID', number: 'Int', title: 'String', state: 'String', body: 'String',
    createdAt: 'String', updatedAt: 'String', closedAt: 'String', author: 'User',
    labels: 'LabelConnection', comments: 'CommentConnection', repository: 'Repository',
  },
  PullRequest: {
    id: 'ID', number: 'Int', title: 'String', state: 'String', body: 'String',
    merged: 'Boolean', mergeable: 'MergeableState', headRefName: 'String', baseRefName: 'String',
    headRefOid: 'String', baseRefOid: 'String', files: 'FileConnection', author: 'User',
    createdAt: 'String', updatedAt: 'String', closedAt: 'String', mergedAt: 'String', repository: 'Repository',
  },
  Comment: { id: 'ID', body: 'String', author: 'User', createdAt: 'String', updatedAt: 'String' },
  FileNode: { path: 'String', additions: 'Int', deletions: 'Int', changeType: 'String' },
  IssueConnection: { nodes: 'Issue', edges: 'IssueEdge', pageInfo: 'PageInfo', totalCount: 'Int' },
  PullRequestConnection: { nodes: 'PullRequest', edges: 'PullRequestEdge', pageInfo: 'PageInfo', totalCount: 'Int' },
  CommentConnection: { nodes: 'Comment', edges: 'CommentEdge', pageInfo: 'PageInfo', totalCount: 'Int' },
  LabelConnection: { nodes: 'Label', edges: 'LabelEdge', pageInfo: 'PageInfo', totalCount: 'Int' },
  FileConnection: { nodes: 'FileNode', edges: 'FileEdge', pageInfo: 'PageInfo', totalCount: 'Int' },
  IssueEdge: { node: 'Issue', cursor: 'String' },
  PullRequestEdge: { node: 'PullRequest', cursor: 'String' },
  CommentEdge: { node: 'Comment', cursor: 'String' },
  LabelEdge: { node: 'Label', cursor: 'String' },
  FileEdge: { node: 'FileNode', cursor: 'String' },
  PageInfo: { hasNextPage: 'Boolean', hasPreviousPage: 'Boolean', startCursor: 'String', endCursor: 'String' },
  BranchRef: { name: 'String', prefix: 'String', target: 'Commit' },
  Commit: { oid: 'String' },
  Label: { id: 'ID', name: 'String', color: 'String', description: 'String' },
  __Type: { name: 'String', kind: 'String', fields: '__Field', enumValues: '__EnumValue' },
  __Field: { name: 'String', description: 'String', args: '__InputValue', type: '__Type' },
  __EnumValue: { name: 'String', description: 'String' },
  __Schema: { queryType: '__Type', mutationType: '__Type', types: '__Type' },
  CreateIssuePayload: { issue: 'Issue', clientMutationId: 'String' },
  CloseIssuePayload: { issue: 'Issue', clientMutationId: 'String' },
  CreatePullRequestPayload: { pullRequest: 'PullRequest', clientMutationId: 'String' },
  MergePullRequestPayload: { pullRequest: 'PullRequest', clientMutationId: 'String' },
  AddCommentPayload: { commentEdge: 'CommentEdge', subject: 'Node', clientMutationId: 'String' },
};

const FIELD_RESOLVERS: Record<string, Record<string, GqlResolver>> = {
  Query: {
    viewer: () => userObject(VIEWER_LOGIN, VIEWER_ID),
    repository: (_parent, args) => {
      const owner = asString(args.owner, '');
      const name = asString(args.name, '');
      if (owner !== VIEWER_LOGIN) return null;
      const repo = lookupRepo(owner, name);
      return repo === undefined ? null : repoObject(repo);
    },
    node: (_parent, args) => resolveGlobalNode(args.id),
    __type: (_parent, args) => introspectionType(args.name),
    __schema: () => ({
      __typename: '__Schema',
      queryType: { __typename: '__Type', name: 'Query', kind: 'OBJECT', fields: null, enumValues: null },
      mutationType: { __typename: '__Type', name: 'Mutation', kind: 'OBJECT', fields: null, enumValues: null },
      types: [],
    }),
  },
  Mutation: {
    createIssue: (_parent, args) => {
      const input = isRecord(args.input) ? args.input : {};
      const repoId = asString(input.repositoryId, '');
      const decoded = decodeGlobalId(repoId);
      if (decoded === null || decoded.kind !== 'R') throw new Error('repositoryId does not name a repository');
      const repo = lookupRepo(decoded.owner, decoded.name);
      if (repo === undefined) throw new Error('repository not found');
      const title = asString(input.title, '');
      if (title === '') throw new Error('title is required');
      const now = nowIso();
      const issue: IssueRec = {
        num: repo.nextNumber, id: nextRecordId, title, body: asString(input.body, ''), state: 'open',
        labels: [], seq: nextSeq, createdAt: now, updatedAt: now, closedAt: null, cachedJson: null,
      };
      nextRecordId += 1;
      nextSeq += 1;
      repo.nextNumber += 1;
      repo.issues.set(issue.num, issue);
      repo.comments.set(issue.num, []);
      repo.repoJsonCache = null;
      return {
        __typename: 'CreateIssuePayload',
        _issue: issueObject(repo, issue),
        clientMutationId: typeof input.clientMutationId === 'string' ? input.clientMutationId : null,
      };
    },
    closeIssue: (_parent, args) => {
      const input = isRecord(args.input) ? args.input : {};
      const node = resolveGlobalNode(input.issueId);
      if (node === null || node.__typename !== 'Issue') throw new Error('issueId does not name an issue');
      const issue = node._issue as IssueRec;
      const repo = node._repo as ForgeRepo;
      issue.state = 'closed';
      issue.closedAt = nowIso();
      issue.updatedAt = nowIso();
      issue.cachedJson = null;
      repo.repoJsonCache = null;
      return {
        __typename: 'CloseIssuePayload',
        _issue: issueObject(repo, issue),
        clientMutationId: typeof input.clientMutationId === 'string' ? input.clientMutationId : null,
      };
    },
    createPullRequest: (_parent, args) => {
      const input = isRecord(args.input) ? args.input : {};
      const repoId = asString(input.repositoryId, '');
      const decoded = decodeGlobalId(repoId);
      if (decoded === null || decoded.kind !== 'R') throw new Error('repositoryId does not name a repository');
      const repo = lookupRepo(decoded.owner, decoded.name);
      if (repo === undefined) throw new Error('repository not found');
      const title = asString(input.title, '');
      const head = asString(input.headRefName, '');
      const base = asString(input.baseRefName, repo.defaultBranch);
      if (title === '' || head === '') throw new Error('title and headRefName are required');
      const headSha = branchTip(repo, head);
      const baseSha = branchTip(repo, base);
      if (headSha === undefined) throw new Error('head branch does not exist');
      if (baseSha === undefined) throw new Error('base branch does not exist');
      if (headSha === baseSha) throw new Error('No commits between head and base');
      const now = nowIso();
      const pull: PullRec = {
        num: repo.nextNumber, id: nextRecordId, title, body: asString(input.body, ''), state: 'open',
        merged: false, mergedAt: null, mergeSha: null, headRef: head, baseRef: base,
        headSha, baseSha, seq: nextSeq, createdAt: now, updatedAt: now, closedAt: null,
      };
      nextRecordId += 1;
      nextSeq += 1;
      repo.nextNumber += 1;
      repo.pulls.set(pull.num, pull);
      repo.comments.set(pull.num, []);
      repo.repoJsonCache = null;
      return {
        __typename: 'CreatePullRequestPayload',
        _pull: pullObject(repo, pull),
        clientMutationId: typeof input.clientMutationId === 'string' ? input.clientMutationId : null,
      };
    },
    mergePullRequest: (_parent, args) => {
      const input = isRecord(args.input) ? args.input : {};
      const node = resolveGlobalNode(input.pullRequestId);
      if (node === null || node.__typename !== 'PullRequest') {
        throw new Error('pullRequestId does not name a pull request');
      }
      const repo = node._repo as ForgeRepo;
      const pull = node._pull as PullRec;
      const fakeCtx: RequestContext = {
        method: 'PUT',
        segments: ['api', 'v3', 'repos', repo.owner, repo.name, 'pulls', String(pull.num), 'merge'],
        query: {},
        bodyText: '{"merge_method":"squash"}',
        headers: {},
        baseUrl: '',
      };
      const result = restMergePull(fakeCtx);
      if (result.status !== 200) {
        throw new Error(`mergePullRequest: the merge was refused (HTTP ${result.status})`);
      }
      return {
        __typename: 'MergePullRequestPayload',
        _pull: pullObject(repo, pull),
        clientMutationId: typeof input.clientMutationId === 'string' ? input.clientMutationId : null,
      };
    },
    addComment: (_parent, args) => {
      const input = isRecord(args.input) ? args.input : {};
      const node = resolveGlobalNode(input.subjectId);
      if (node === null || (node.__typename !== 'Issue' && node.__typename !== 'PullRequest')) {
        throw new Error('subjectId does not name an issue or pull request');
      }
      const repo = node._repo as ForgeRepo;
      const num = (node._issue as IssueRec | undefined)?.num ?? (node._pull as PullRec | undefined)?.num;
      if (num === undefined) throw new Error('subjectId does not name an issue or pull request');
      const body = asString(input.body, '');
      if (body === '') throw new Error('body is required');
      const now = nowIso();
      const comment: CommentRec = { id: nextRecordId, body, createdAt: now, updatedAt: now };
      nextRecordId += 1;
      const list = repo.comments.get(num) ?? [];
      list.push(comment);
      repo.comments.set(num, list);
      const issue = repo.issues.get(num);
      if (issue !== undefined) issue.cachedJson = null;
      return {
        __typename: 'AddCommentPayload',
        _comment: commentObject(repo, num, comment),
        _subject: node,
        clientMutationId: typeof input.clientMutationId === 'string' ? input.clientMutationId : null,
      };
    },
  },
  User: {
    login: (parent) => parent.login ?? null,
    id: (parent) => userGlobalId(asString(parent.login, ''), asNumber(parent.id, 0)),
    name: (parent) => parent.name ?? null,
    email: (parent) => parent.email ?? null,
    databaseId: (parent) => asNumber(parent.id, 0),
  },
  Repository: {
    id: (parent) => globalId('R', (parent._repo as ForgeRepo).owner, (parent._repo as ForgeRepo).name, (parent._repo as ForgeRepo).id),
    databaseId: (parent) => (parent._repo as ForgeRepo).id,
    name: (parent) => (parent._repo as ForgeRepo).name,
    nameWithOwner: (parent) => `${(parent._repo as ForgeRepo).owner}/${(parent._repo as ForgeRepo).name}`,
    owner: (parent) => userObject((parent._repo as ForgeRepo).owner, VIEWER_ID),
    defaultBranchRef: (parent) => {
      const repo = parent._repo as ForgeRepo;
      const tip = branchTip(repo, repo.defaultBranch);
      if (tip === undefined) return null;
      return { __typename: 'BranchRef', name: repo.defaultBranch, _repo: repo };
    },
    viewerPermission: () => 'ADMIN',
    hasIssuesEnabled: () => true,
    issue: (parent, args) => {
      const repo = parent._repo as ForgeRepo;
      const num = asNumber(args.number, -1);
      const issue = repo.issues.get(num);
      return issue === undefined ? null : issueObject(repo, issue);
    },
    issues: (parent, args) => {
      const repo = parent._repo as ForgeRepo;
      let issues = [...repo.issues.values()];
      if (Array.isArray(args.states)) {
        const wanted = new Set(args.states.map((state) => String(state)));
        issues = issues.filter((issue) => wanted.has(issue.state === 'open' ? 'OPEN' : 'CLOSED'));
      }
      const orderBy = isRecord(args.orderBy) ? args.orderBy : {};
      const direction = asString(orderBy.direction, 'DESC');
      issues.sort((a, b) => (direction === 'ASC' ? a.seq - b.seq : b.seq - a.seq));
      const first = typeof args.first === 'number' ? args.first : null;
      const after = typeof args.after === 'string' ? args.after : null;
      const connection = makeConnection(
        'IssueConnection',
        issues,
        first,
        after,
        (issue) => cursorForSeq(issue.seq),
        (cursor) => {
          const seq = seqFromCursor(cursor);
          if (seq === null) return -1;
          return issues.findIndex((issue) => issue.seq === seq);
        },
      );
      return { ...connection, nodes: connection.nodes.map((issue) => issueObject(repo, issue)) };
    },
    pullRequest: (parent, args) => {
      const repo = parent._repo as ForgeRepo;
      const num = asNumber(args.number, -1);
      const pull = repo.pulls.get(num);
      return pull === undefined ? null : pullObject(repo, pull);
    },
    pullRequests: (parent, args) => {
      const repo = parent._repo as ForgeRepo;
      let pulls = [...repo.pulls.values()];
      if (Array.isArray(args.states)) {
        const wanted = new Set(args.states.map((state) => String(state)));
        pulls = pulls.filter((pull) => {
          const state = pull.merged ? 'MERGED' : pull.state === 'open' ? 'OPEN' : 'CLOSED';
          return wanted.has(state);
        });
      }
      pulls.sort((a, b) => b.seq - a.seq);
      const first = typeof args.first === 'number' ? args.first : null;
      const after = typeof args.after === 'string' ? args.after : null;
      const connection = makeConnection(
        'PullRequestConnection',
        pulls,
        first,
        after,
        (pull) => cursorForSeq(pull.seq),
        (cursor) => {
          const seq = seqFromCursor(cursor);
          if (seq === null) return -1;
          return pulls.findIndex((pull) => pull.seq === seq);
        },
      );
      return { ...connection, nodes: connection.nodes.map((pull) => pullObject(repo, pull)) };
    },
    url: (parent) => `https://github.com/${(parent._repo as ForgeRepo).owner}/${(parent._repo as ForgeRepo).name}`,
    html_url: (parent) => `https://github.com/${(parent._repo as ForgeRepo).owner}/${(parent._repo as ForgeRepo).name}`,
  },
  Issue: {
    id: (parent) => globalId('I', (parent._repo as ForgeRepo).owner, (parent._repo as ForgeRepo).name, (parent._issue as IssueRec).num),
    number: (parent) => (parent._issue as IssueRec).num,
    title: (parent) => (parent._issue as IssueRec).title,
    state: (parent) => ((parent._issue as IssueRec).state === 'open' ? 'OPEN' : 'CLOSED'),
    body: (parent) => (parent._issue as IssueRec).body,
    createdAt: (parent) => (parent._issue as IssueRec).createdAt,
    updatedAt: (parent) => (parent._issue as IssueRec).updatedAt,
    closedAt: (parent) => (parent._issue as IssueRec).closedAt,
    author: () => userObject(VIEWER_LOGIN, VIEWER_ID),
    labels: (parent, args) => {
      const repo = parent._repo as ForgeRepo;
      const issue = parent._issue as IssueRec;
      const nodes = issue.labels.map((name) => {
        const label = repo.labels.get(name);
        return {
          __typename: 'Label',
          name,
          color: label?.color ?? '',
          description: '',
          id: base64UrlEncode(`L|${repo.owner}/${repo.name}|${name}`),
        };
      });
      const first = typeof args.first === 'number' ? args.first : null;
      return makeConnection('LabelConnection', nodes, first, null, (_node, index) => cursorForSeq(index + 1), () => -1);
    },
    comments: (parent, args) => {
      const repo = parent._repo as ForgeRepo;
      const issue = parent._issue as IssueRec;
      const comments = repo.comments.get(issue.num) ?? [];
      const first = typeof args.first === 'number' ? args.first : null;
      const after = typeof args.after === 'string' ? args.after : null;
      const connection = makeConnection(
        'CommentConnection',
        comments,
        first,
        after,
        (comment) => cursorForSeq(comment.id),
        (cursor) => {
          const seq = seqFromCursor(cursor);
          if (seq === null) return -1;
          return comments.findIndex((comment) => comment.id === seq);
        },
      );
      return { ...connection, nodes: connection.nodes.map((comment) => commentObject(repo, issue.num, comment)) };
    },
    repository: (parent) => repoObject(parent._repo as ForgeRepo),
  },
  PullRequest: {
    id: (parent) => globalId('P', (parent._repo as ForgeRepo).owner, (parent._repo as ForgeRepo).name, (parent._pull as PullRec).num),
    number: (parent) => (parent._pull as PullRec).num,
    title: (parent) => (parent._pull as PullRec).title,
    state: (parent) => {
      const pull = parent._pull as PullRec;
      if (pull.merged) return 'MERGED';
      return pull.state === 'open' ? 'OPEN' : 'CLOSED';
    },
    body: (parent) => (parent._pull as PullRec).body,
    merged: (parent) => (parent._pull as PullRec).merged,
    mergeable: (parent) => {
      const pull = parent._pull as PullRec;
      if (pull.state !== 'open' || pull.merged) return 'UNKNOWN';
      return 'MERGEABLE';
    },
    headRefName: (parent) => (parent._pull as PullRec).headRef,
    baseRefName: (parent) => (parent._pull as PullRec).baseRef,
    headRefOid: (parent) => (parent._pull as PullRec).headSha,
    baseRefOid: (parent) => (parent._pull as PullRec).baseSha,
    files: (parent, args) => {
      const repo = parent._repo as ForgeRepo;
      const pull = parent._pull as PullRec;
      const baseObject = repo.objects.get(pull.baseSha);
      const headObject = repo.objects.get(pull.headSha);
      let nodes: GqlParent[] = [];
      if (baseObject !== undefined && headObject !== undefined && baseObject.kind === 'commit' && headObject.kind === 'commit') {
        const baseTree = parseCommit(baseObject.bytes).tree;
        const headTree = parseCommit(headObject.bytes).tree;
        const diffs = treeDiff(repo, baseTree, headTree);
        nodes = diffs.map((diff) => {
          const counts = countLineChanges(repo, diff.baseBlob, diff.headBlob);
          return {
            __typename: 'FileNode',
            path: diff.path,
            additions: counts.additions,
            deletions: counts.deletions,
            changeType: diff.status === 'added' ? 'ADDED' : diff.status === 'removed' ? 'REMOVED' : 'MODIFIED',
          };
        });
      }
      const first = typeof args.first === 'number' ? args.first : null;
      const after = typeof args.after === 'string' ? args.after : null;
      return makeConnection(
        'FileConnection',
        nodes,
        first,
        after,
        (_node, index) => fileCursorForIndex(index),
        (cursor) => {
          const index = indexFromCursor(cursor);
          return index === null ? -1 : index;
        },
      );
    },
    author: () => userObject(VIEWER_LOGIN, VIEWER_ID),
    createdAt: (parent) => (parent._pull as PullRec).createdAt,
    updatedAt: (parent) => (parent._pull as PullRec).updatedAt,
    closedAt: (parent) => (parent._pull as PullRec).closedAt,
    mergedAt: (parent) => (parent._pull as PullRec).mergedAt,
    repository: (parent) => repoObject(parent._repo as ForgeRepo),
  },
  Comment: {
    id: (parent) => globalId('C', (parent._repo as ForgeRepo).owner, (parent._repo as ForgeRepo).name, parent._num as number, `${(parent._comment as CommentRec).id}`),
    body: (parent) => (parent._comment as CommentRec).body,
    author: () => userObject(VIEWER_LOGIN, VIEWER_ID),
    createdAt: (parent) => (parent._comment as CommentRec).createdAt,
    updatedAt: (parent) => (parent._comment as CommentRec).updatedAt,
  },
  FileNode: {
    path: (parent) => parent.path ?? null,
    additions: (parent) => asNumber(parent.additions, 0),
    deletions: (parent) => asNumber(parent.deletions, 0),
    changeType: (parent) => parent.changeType ?? null,
  },
  IssueConnection: {
    nodes: (parent) => (parent as unknown as GqlConnection<GqlParent>).nodes,
    edges: (parent) => {
      const connection = parent as unknown as GqlConnection<GqlParent>;
      return connection.nodes.map((node, index) => ({
        __typename: 'IssueEdge',
        node,
        cursor: cursorForSeq(((node._issue as IssueRec | undefined)?.seq ?? index + 1) as number),
      }));
    },
    pageInfo: (parent) => (parent as unknown as GqlConnection<GqlParent>).pageInfo,
    totalCount: (parent) => (parent as unknown as GqlConnection<GqlParent>).totalCount,
  },
  PullRequestConnection: {
    nodes: (parent) => (parent as unknown as GqlConnection<GqlParent>).nodes,
    edges: (parent) => {
      const connection = parent as unknown as GqlConnection<GqlParent>;
      return connection.nodes.map((node, index) => ({
        __typename: 'PullRequestEdge',
        node,
        cursor: cursorForSeq(((node._pull as PullRec | undefined)?.seq ?? index + 1) as number),
      }));
    },
    pageInfo: (parent) => (parent as unknown as GqlConnection<GqlParent>).pageInfo,
    totalCount: (parent) => (parent as unknown as GqlConnection<GqlParent>).totalCount,
  },
  CommentConnection: {
    nodes: (parent) => (parent as unknown as GqlConnection<GqlParent>).nodes,
    edges: (parent) => {
      const connection = parent as unknown as GqlConnection<GqlParent>;
      return connection.nodes.map((node) => ({
        __typename: 'CommentEdge',
        node,
        cursor: cursorForSeq(((node._comment as CommentRec | undefined)?.id ?? 0) as number),
      }));
    },
    pageInfo: (parent) => (parent as unknown as GqlConnection<GqlParent>).pageInfo,
    totalCount: (parent) => (parent as unknown as GqlConnection<GqlParent>).totalCount,
  },
  LabelConnection: {
    nodes: (parent) => (parent as unknown as GqlConnection<GqlParent>).nodes,
    edges: (parent) => {
      const connection = parent as unknown as GqlConnection<GqlParent>;
      return connection.nodes.map((node, index) => ({ __typename: 'LabelEdge', node, cursor: cursorForSeq(index + 1) }));
    },
    pageInfo: (parent) => (parent as unknown as GqlConnection<GqlParent>).pageInfo,
    totalCount: (parent) => (parent as unknown as GqlConnection<GqlParent>).totalCount,
  },
  FileConnection: {
    nodes: (parent) => (parent as unknown as GqlConnection<GqlParent>).nodes,
    edges: (parent) => {
      const connection = parent as unknown as GqlConnection<GqlParent>;
      return connection.nodes.map((node, index) => ({ __typename: 'FileEdge', node, cursor: fileCursorForIndex(index) }));
    },
    pageInfo: (parent) => (parent as unknown as GqlConnection<GqlParent>).pageInfo,
    totalCount: (parent) => (parent as unknown as GqlConnection<GqlParent>).totalCount,
  },
  IssueEdge: { node: (parent) => parent.node ?? null, cursor: (parent) => parent.cursor ?? null },
  PullRequestEdge: { node: (parent) => parent.node ?? null, cursor: (parent) => parent.cursor ?? null },
  CommentEdge: { node: (parent) => parent.node ?? null, cursor: (parent) => parent.cursor ?? null },
  LabelEdge: { node: (parent) => parent.node ?? null, cursor: (parent) => parent.cursor ?? null },
  FileEdge: { node: (parent) => parent.node ?? null, cursor: (parent) => parent.cursor ?? null },
  PageInfo: {
    hasNextPage: (parent) => (parent as { hasNextPage: boolean }).hasNextPage,
    hasPreviousPage: (parent) => (parent as { hasPreviousPage: boolean }).hasPreviousPage,
    startCursor: (parent) => (parent as { startCursor: string | null }).startCursor,
    endCursor: (parent) => (parent as { endCursor: string | null }).endCursor,
  },
  BranchRef: {
    name: (parent) => parent.name ?? null,
    prefix: () => 'refs/heads/',
    target: (parent) => {
      const repo = parent._repo as ForgeRepo;
      const tip = branchTip(repo, asString(parent.name, ''));
      return tip === undefined ? null : { __typename: 'Commit', oid: tip };
    },
  },
  Commit: { oid: (parent) => parent.oid ?? null },
  Label: {
    id: (parent) => parent.id ?? null,
    name: (parent) => parent.name ?? null,
    color: (parent) => parent.color ?? null,
    description: (parent) => parent.description ?? null,
  },
  __Type: {
    name: (parent) => parent.name ?? null,
    kind: (parent) => parent.kind ?? null,
    fields: (parent) => parent.fields ?? null,
    enumValues: (parent) => parent.enumValues ?? null,
  },
  __Field: {
    name: (parent) => parent.name ?? null,
    description: (parent) => parent.description ?? null,
    args: () => [],
    type: () => null,
  },
  __EnumValue: {
    name: (parent) => parent.name ?? null,
    description: (parent) => parent.description ?? null,
  },
  __Schema: {
    queryType: (parent) => parent.queryType ?? null,
    mutationType: (parent) => parent.mutationType ?? null,
    types: () => [],
  },
  CreateIssuePayload: {
    issue: (parent) => parent._issue ?? null,
    clientMutationId: (parent) => parent.clientMutationId ?? null,
  },
  CloseIssuePayload: {
    issue: (parent) => parent._issue ?? null,
    clientMutationId: (parent) => parent.clientMutationId ?? null,
  },
  CreatePullRequestPayload: {
    pullRequest: (parent) => parent._pull ?? null,
    clientMutationId: (parent) => parent.clientMutationId ?? null,
  },
  MergePullRequestPayload: {
    pullRequest: (parent) => parent._pull ?? null,
    clientMutationId: (parent) => parent.clientMutationId ?? null,
  },
  AddCommentPayload: {
    commentEdge: (parent) => ({ __typename: 'CommentEdge', node: parent._comment ?? null, cursor: '' }),
    subject: (parent) => parent._subject ?? null,
    clientMutationId: (parent) => parent.clientMutationId ?? null,
  },
};

interface GqlError {
  readonly message: string;
  readonly path: string[];
}

function executeSelections(
  parent: GqlParent,
  parentType: string,
  selections: readonly GqlSelection[],
  doc: GqlDocument,
  variables: ReadonlyMap<string, unknown>,
  errors: GqlError[],
  path: string[],
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const selection of selections) {
    if (selection.kind === 'fragment') {
      const fragment = doc.fragments.get(selection.name);
      if (fragment === undefined) {
        errors.push({ message: `Unknown fragment "${selection.name}".`, path: [...path] });
        continue;
      }
      if (fragment.typeCondition !== parentType && fragment.typeCondition !== 'Node') continue;
      const expanded = executeSelections(parent, parentType, fragment.selections, doc, variables, errors, path);
      Object.assign(out, expanded);
      continue;
    }
    if (selection.kind === 'inline') {
      if (selection.typeCondition !== null && selection.typeCondition !== parentType && selection.typeCondition !== 'Node') continue;
      const expanded = executeSelections(parent, parentType, selection.selections, doc, variables, errors, path);
      Object.assign(out, expanded);
      continue;
    }
    const field = selection.field;
    const key = field.alias ?? field.name;
    if (field.name === '__typename') {
      out[key] = parentType;
      continue;
    }
    const resolvers = FIELD_RESOLVERS[parentType];
    const resolver = resolvers?.[field.name];
    if (resolver === undefined) {
      errors.push({ message: `Cannot query field "${field.name}" on type "${parentType}".`, path: [...path, key] });
      out[key] = null;
      continue;
    }
    let value: unknown;
    try {
      value = resolver(parent, gqlResolveArgs(field.args, variables));
    } catch (error) {
      errors.push({ message: (error as Error).message, path: [...path, key] });
      out[key] = null;
      continue;
    }
    if (field.selections === null) {
      out[key] = value;
      continue;
    }
    if (value === null || value === undefined) {
      out[key] = null;
      continue;
    }
    const childType = FIELD_TYPES[parentType]?.[field.name] ?? 'String';
    if (Array.isArray(value)) {
      out[key] = value.map((item) => {
        if (!isRecord(item)) return item;
        const itemType = typeof item.__typename === 'string' ? item.__typename : childType;
        return executeSelections(item as GqlParent, itemType, field.selections as GqlSelection[], doc, variables, errors, [...path, key]);
      });
      continue;
    }
    if (isRecord(value)) {
      const child = value as GqlParent;
      out[key] = executeSelections(child, child.__typename ?? childType, field.selections, doc, variables, errors, [...path, key]);
      continue;
    }
    out[key] = value;
  }
  return out;
}

function executeGraphQLDocument(
  query: string,
  variables: Record<string, unknown>,
): { data: Record<string, unknown> | null; errors?: GqlError[] } {
  let doc: GqlDocument;
  try {
    doc = new GqlParser(tokenizeGraphQL(query)).parseDocument();
  } catch (error) {
    return { data: null, errors: [{ message: (error as Error).message, path: [] }] };
  }
  if (doc.operations.length === 0) {
    return { data: null, errors: [{ message: 'No operation in GraphQL document.', path: [] }] };
  }
  const operation = doc.operations[0] as GqlOperation;
  const variableValues = new Map<string, unknown>();
  for (const [name, definition] of operation.variables) {
    if (name in variables) variableValues.set(name, variables[name]);
    else if (definition.defaultValue !== null) variableValues.set(name, gqlResolveValue(definition.defaultValue, variableValues));
    else variableValues.set(name, null);
  }
  for (const [name, value] of Object.entries(variables)) {
    if (!variableValues.has(name)) variableValues.set(name, value);
  }
  const errors: GqlError[] = [];
  const root: GqlParent = {};
  const rootType = operation.operation === 'mutation' ? 'Mutation' : 'Query';
  const data = executeSelections(root, rootType, operation.selections, doc, variableValues, errors, []);
  if (errors.length > 0) return { data, errors };
  return { data };
}

function restGraphQL(ctx: RequestContext): ForgeResponse {
  const parsed = requestJson(ctx);
  if (!parsed.ok) return errorResponse(400, 'Problems parsing JSON');
  const body = parsed.value;
  if (Array.isArray(body)) {
    const results = body.map((item) => {
      if (!isRecord(item) || typeof item.query !== 'string') {
        return { data: null, errors: [{ message: 'Each batched document needs a query string.', path: [] }] };
      }
      const variables = isRecord(item.variables) ? (item.variables as Record<string, unknown>) : {};
      return executeGraphQLDocument(item.query, variables);
    });
    return jsonResponse(200, results);
  }
  if (!isRecord(body) || typeof body.query !== 'string') {
    return errorResponse(400, 'A query string is required');
  }
  const variables = isRecord(body.variables) ? (body.variables as Record<string, unknown>) : {};
  const result = executeGraphQLDocument(body.query, variables);
  return jsonResponse(200, result);
}

// ---------------------------------------------------------------------------
// MCP: streamable HTTP, modern era (2026-07-28) with a legacy fallback
// ---------------------------------------------------------------------------

interface McpToolDef {
  readonly name: string;
  readonly description: string;
  readonly inputSchema: {
    readonly type: 'object';
    readonly properties: Record<string, Record<string, unknown>>;
    readonly required: string[];
  };
}

/** The six tools, built once so tools/list is byte-identical on every call. */
const MCP_TOOLS: readonly McpToolDef[] = [
  {
    name: 'create_repo',
    description: 'Create a repository owned by the authenticated user.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The owner login (the authenticated user).' },
        name: { type: 'string', description: 'The repository name.' },
        description: { type: 'string', description: 'A short description of the repository.' },
        private: { type: 'boolean', description: 'Whether the repository is private.' },
      },
      required: ['name'],
    },
  },
  {
    name: 'get_repo',
    description: 'Read one repository by owner and name.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
        full_name: { type: 'string', description: 'The repository full name, "owner/repo".' },
      },
      required: [],
    },
  },
  {
    name: 'create_issue',
    description: 'Create an issue in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
        full_name: { type: 'string', description: 'The repository full name, "owner/repo".' },
        title: { type: 'string', description: 'The issue title.' },
        body: { type: 'string', description: 'The issue body.' },
        labels: { type: 'array', items: { type: 'string' }, description: 'Label names to apply.' },
      },
      required: ['title'],
    },
  },
  {
    name: 'list_issues',
    description: 'List the issues of a repository, optionally filtered by state.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
        full_name: { type: 'string', description: 'The repository full name, "owner/repo".' },
        state: { type: 'string', description: 'open, closed, or all.' },
        per_page: { type: 'integer', description: 'Page size.' },
        page: { type: 'integer', description: 'Page number.' },
      },
      required: [],
    },
  },
  {
    name: 'create_pull_request',
    description: 'Open a pull request from one branch onto another.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
        full_name: { type: 'string', description: 'The repository full name, "owner/repo".' },
        title: { type: 'string', description: 'The pull request title.' },
        body: { type: 'string', description: 'The pull request body.' },
        head: { type: 'string', description: 'The head branch name.' },
        base: { type: 'string', description: 'The base branch name.' },
      },
      required: ['title', 'head', 'base'],
    },
  },
  {
    name: 'merge_pull_request',
    description: 'Merge a pull request with a squash commit.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
        full_name: { type: 'string', description: 'The repository full name, "owner/repo".' },
        pull_number: { type: 'integer', description: 'The pull request number.' },
        number: { type: 'integer', description: 'The pull request number.' },
        merge_method: { type: 'string', description: 'squash, merge, or rebase.' },
      },
      required: ['pull_number'],
    },
  },
];

const MCP_VERSIONS = ['2026-07-28', '2025-11-25', '2025-06-18', '2025-03-26'];

/** Resolve a repository from tool arguments: full_name, or owner + repo (with synonyms). */
function mcpResolveRepo(args: Record<string, unknown>): ForgeRepo | null {
  const fullName = asString(args.full_name ?? args.fullName, '');
  if (fullName !== '') {
    const slash = fullName.indexOf('/');
    if (slash > 0) {
      const owner = fullName.slice(0, slash);
      const name = fullName.slice(slash + 1);
      if (owner !== VIEWER_LOGIN) return null;
      return lookupRepo(owner, name) ?? null;
    }
  }
  const owner = asString(args.owner ?? args.owner_login ?? args.user ?? args.login, VIEWER_LOGIN);
  const name = asString(args.repo ?? args.repository ?? args.name, '');
  if (owner !== VIEWER_LOGIN || name === '') return null;
  return lookupRepo(owner, name) ?? null;
}

function mcpArgString(args: Record<string, unknown>, keys: readonly string[]): string {
  for (const key of keys) {
    const value = args[key];
    if (typeof value === 'string' && value !== '') return value;
  }
  return '';
}

function mcpArgNumber(args: Record<string, unknown>, keys: readonly string[]): number | null {
  for (const key of keys) {
    const value = args[key];
    if (typeof value === 'number' && Number.isFinite(value)) return value;
  }
  return null;
}

function mcpMissingRequired(tool: McpToolDef, args: Record<string, unknown>): string[] {
  return tool.inputSchema.required.filter((name) => {
    const value = args[name];
    return value === undefined || value === null || value === '';
  });
}

function mcpToolResult(value: unknown, isError = false): Record<string, unknown> {
  const text = typeof value === 'string' ? value : toJson(value);
  const out: Record<string, unknown> = {
    content: [{ type: 'text', text }],
    isError,
  };
  if (!isError && isRecord(value)) out.structuredContent = value;
  return out;
}

function mcpCallTool(name: string, args: Record<string, unknown>): { result: Record<string, unknown> } | { error: { code: number; message: string } } {
  const tool = MCP_TOOLS.find((candidate) => candidate.name === name);
  if (tool === undefined) return { error: { code: -32602, message: `Unknown tool: ${name}` } };
  const missing = mcpMissingRequired(tool, args);
  if (missing.length > 0) {
    return { result: mcpToolResult({ error: `missing required argument: ${missing.join(', ')}` }, true) };
  }
  try {
    switch (name) {
      case 'create_repo': {
        const repoName = mcpArgString(args, ['name']);
        const description = mcpArgString(args, ['description']);
        const isPrivate = args.private === true;
        if (repoName === '' || repoName.length > 100 || !/^[A-Za-z0-9._-]+$/.test(repoName)) {
          return { result: mcpToolResult({ error: 'Repository name is invalid' }, true) };
        }
        if (lookupRepo(VIEWER_LOGIN, repoName) !== undefined) {
          return { result: mcpToolResult({ error: 'Repository already exists' }, true) };
        }
        const repo = createForgeRepo(VIEWER_LOGIN, repoName, description, isPrivate);
        return { result: mcpToolResult(JSON.parse(repoJson(repo).toString('utf8')) as Record<string, unknown>) };
      }
      case 'get_repo': {
        const repo = mcpResolveRepo(args);
        if (repo === null) return { result: mcpToolResult({ error: 'Repository not found' }, true) };
        return { result: mcpToolResult(JSON.parse(repoJson(repo).toString('utf8')) as Record<string, unknown>) };
      }
      case 'create_issue': {
        const repo = mcpResolveRepo(args);
        if (repo === null) return { result: mcpToolResult({ error: 'Repository not found' }, true) };
        const title = mcpArgString(args, ['title']);
        const body = mcpArgString(args, ['body', 'description', 'content']);
        const labels: string[] = [];
        if (Array.isArray(args.labels)) {
          for (const label of args.labels) {
            if (typeof label !== 'string' || !repo.labels.has(label)) {
              return { result: mcpToolResult({ error: `unknown label ${String(label)}` }, true) };
            }
            labels.push(label);
          }
        }
        const now = nowIso();
        const issue: IssueRec = {
          num: repo.nextNumber, id: nextRecordId, title, body, state: 'open',
          labels, seq: nextSeq, createdAt: now, updatedAt: now, closedAt: null, cachedJson: null,
        };
        nextRecordId += 1;
        nextSeq += 1;
        repo.nextNumber += 1;
        repo.issues.set(issue.num, issue);
        repo.comments.set(issue.num, []);
        repo.repoJsonCache = null;
        return { result: mcpToolResult(JSON.parse(issueJson(repo, issue).toString('utf8')) as Record<string, unknown>) };
      }
      case 'list_issues': {
        const repo = mcpResolveRepo(args);
        if (repo === null) return { result: mcpToolResult({ error: 'Repository not found' }, true) };
        const state = mcpArgString(args, ['state']) || 'open';
        let items = issueListItems(repo);
        if (state !== 'all') items = items.filter((item) => item.state === state);
        const perPage = mcpArgNumber(args, ['per_page']) ?? 30;
        const page = mcpArgNumber(args, ['page']) ?? 1;
        const start = (page - 1) * perPage;
        return { result: mcpToolResult(items.slice(start, start + perPage)) };
      }
      case 'create_pull_request': {
        const repo = mcpResolveRepo(args);
        if (repo === null) return { result: mcpToolResult({ error: 'Repository not found' }, true) };
        const title = mcpArgString(args, ['title']);
        const body = mcpArgString(args, ['body', 'description', 'content']);
        const head = mcpArgString(args, ['head', 'head_ref', 'head_branch']);
        const base = mcpArgString(args, ['base', 'base_ref', 'base_branch']) || repo.defaultBranch;
        const headSha = branchTip(repo, head);
        const baseSha = branchTip(repo, base);
        if (headSha === undefined) return { result: mcpToolResult({ error: 'Invalid head branch' }, true) };
        if (baseSha === undefined) return { result: mcpToolResult({ error: 'Invalid base branch' }, true) };
        if (headSha === baseSha) return { result: mcpToolResult({ error: 'No commits between head and base' }, true) };
        const now = nowIso();
        const pull: PullRec = {
          num: repo.nextNumber, id: nextRecordId, title, body, state: 'open',
          merged: false, mergedAt: null, mergeSha: null, headRef: head, baseRef: base,
          headSha, baseSha, seq: nextSeq, createdAt: now, updatedAt: now, closedAt: null,
        };
        nextRecordId += 1;
        nextSeq += 1;
        repo.nextNumber += 1;
        repo.pulls.set(pull.num, pull);
        repo.comments.set(pull.num, []);
        repo.repoJsonCache = null;
        return { result: mcpToolResult(pullJson(repo, pull)) };
      }
      case 'merge_pull_request': {
        const repo = mcpResolveRepo(args);
        if (repo === null) return { result: mcpToolResult({ error: 'Repository not found' }, true) };
        const num = mcpArgNumber(args, ['pull_number', 'pull_request_number', 'pr_number', 'number']);
        if (num === null) return { result: mcpToolResult({ error: 'missing required argument: pull_number' }, true) };
        const pull = repo.pulls.get(num);
        if (pull === undefined) return { result: mcpToolResult({ error: 'Pull request not found' }, true) };
        if (pull.merged) return { result: mcpToolResult({ error: 'Pull Request is already merged' }, true) };
        const method = mcpArgString(args, ['merge_method']) || 'squash';
        const merged = mergePullInternal(repo, pull, method);
        if (merged === null) return { result: mcpToolResult({ error: 'Pull request is not mergeable' }, true) };
        return { result: mcpToolResult({ merged: true, sha: merged, message: `Merge pull request #${num} from ${repo.owner}:${pull.headRef}` }) };
      }
      default:
        return { error: { code: -32602, message: `Unknown tool: ${name}` } };
    }
  } catch (error) {
    return { result: mcpToolResult({ error: (error as Error).message }, true) };
  }
}

/**
 * The shared squash-merge core (also used by the REST merge handler's twin):
 * overlay the head's changes since the merge-base onto the base tip.
 * Returns the merge commit id, or null when the pull cannot merge cleanly.
 */
function mergePullInternal(repo: ForgeRepo, pull: PullRec, method: string): string | null {
  const baseObject = repo.objects.get(pull.baseSha);
  const headObject = repo.objects.get(pull.headSha);
  if (baseObject === undefined || headObject === undefined) return null;
  if (baseObject.kind !== 'commit' || headObject.kind !== 'commit') return null;
  const baseTip = branchTip(repo, pull.baseRef);
  if (baseTip !== undefined && baseTip !== pull.baseSha) pull.baseSha = baseTip;
  if (pull.baseSha === pull.headSha) return null;
  const base = mergeBase(repo, pull.baseSha, pull.headSha);
  if (base === null) return null;
  const baseCommit = repo.objects.get(base);
  const headCommit = repo.objects.get(pull.headSha);
  const tipCommit = repo.objects.get(pull.baseSha);
  if (baseCommit === undefined || headCommit === undefined || tipCommit === undefined) return null;
  const baseTree = parseCommit(baseCommit.bytes).tree;
  const headTree = parseCommit(headCommit.bytes).tree;
  const tipTree = parseCommit(tipCommit.bytes).tree;
  const headChanges = treeDiff(repo, baseTree, headTree);
  const baseChanges = treeDiff(repo, baseTree, tipTree);
  const baseChanged = new Map<string, string | null>();
  for (const change of baseChanges) baseChanged.set(change.path, change.headBlob);
  for (const change of headChanges) {
    if (baseChanged.has(change.path) && baseChanged.get(change.path) !== change.headBlob) return null;
  }
  let mergedTree = tipTree;
  for (const change of headChanges) {
    mergedTree = treeSetPath(repo, mergedTree, change.path, change.headBlob);
  }
  const message = `Merge pull request #${pull.num} from ${repo.owner}:${pull.headRef}`;
  const parents = method === 'merge' ? [pull.baseSha, pull.headSha] : [pull.baseSha];
  const commitOid = putObject(repo, 'commit', buildCommit(mergedTree, parents, message, nowEpoch()));
  setRef(repo, branchRef(pull.baseRef), commitOid);
  const now = nowIso();
  pull.merged = true;
  pull.mergedAt = now;
  pull.mergeSha = commitOid;
  pull.state = 'closed';
  pull.closedAt = now;
  pull.updatedAt = now;
  repo.repoJsonCache = null;
  return commitOid;
}

function mcpHandleRequest(ctx: RequestContext): ForgeResponse {
  if (ctx.method === 'DELETE') {
    return { status: 200, body: Buffer.alloc(0), contentType: 'application/json', headers: {} };
  }
  if (ctx.method === 'GET') {
    return errorResponse(405, 'Method Not Allowed');
  }
  if (ctx.method !== 'POST') return errorResponse(405, 'Method Not Allowed');
  const parsed = requestJson(ctx);
  if (!parsed.ok) {
    return jsonResponse(400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
  }
  if (!isRecord(parsed.value)) {
    return jsonResponse(400, { jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Invalid Request' } });
  }
  const body = parsed.value;
  const id = body.id ?? null;
  const method = asString(body.method, '');
  const params = isRecord(body.params) ? body.params : {};
  // A notification (no id) is acknowledged with 202 and no body.
  if (id === null && body.id === undefined) {
    if (method === 'notifications/initialized' || method.startsWith('notifications/')) {
      return { status: 202, body: Buffer.alloc(0), contentType: 'application/json', headers: {} };
    }
    return jsonResponse(400, { jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Invalid Request' } });
  }
  const ok = (result: unknown): ForgeResponse => jsonResponse(200, { jsonrpc: '2.0', id, result });
  const fail = (code: number, message: string): ForgeResponse =>
    jsonResponse(200, { jsonrpc: '2.0', id, error: { code, message } });
  switch (method) {
    case 'server/discover':
      return ok({
        supportedVersions: [...MCP_VERSIONS],
        protocolVersion: MCP_VERSIONS[0],
        serverInfo: { name: 'forge', version: '1.0.0' },
        capabilities: { tools: { listChanged: false } },
      });
    case 'initialize': {
      const requested = isRecord(params) ? asString(params.protocolVersion, '') : '';
      const version = MCP_VERSIONS.includes(requested) ? requested : '2025-11-25';
      return ok({
        protocolVersion: version,
        serverInfo: { name: 'forge', version: '1.0.0' },
        capabilities: { tools: {} },
      });
    }
    case 'ping':
      return ok({});
    case 'tools/list':
      return ok({ tools: MCP_TOOLS });
    case 'tools/call': {
      const toolName = asString(params.name, '');
      const args = isRecord(params.arguments) ? (params.arguments as Record<string, unknown>) : {};
      const outcome = mcpCallTool(toolName, args);
      if ('error' in outcome) return fail(outcome.error.code, outcome.error.message);
      return ok(outcome.result);
    }
    default:
      return fail(-32601, `Method not found: ${method}`);
  }
}

// ---------------------------------------------------------------------------
// HTTP server: routing, authentication, the request envelope
// ---------------------------------------------------------------------------

let requestCounter = 0;

function isAuthenticated(headers: Record<string, string | string[] | undefined>): boolean {
  const expected = shopToken();
  if (expected === '') return true;
  const header = headers.authorization;
  const value = Array.isArray(header) ? header[0] : header;
  return value === `Bearer ${expected}`;
}

function headerString(headers: Record<string, string | string[] | undefined>, name: string): string {
  const value = headers[name.toLowerCase()];
  if (value === undefined) return '';
  return Array.isArray(value) ? (value[0] ?? '') : value;
}

function writeResponse(res: nodeHttp.ServerResponse, response: ForgeResponse, requestId: string): void {
  const headers: Record<string, string> = {
    'Content-Type': response.contentType,
    'X-GitHub-Request-Id': requestId,
    ...response.headers,
  };
  if (response.status === 204) {
    res.writeHead(204, headers);
    res.end();
    return;
  }
  headers['Content-Length'] = String(response.body.length);
  res.writeHead(response.status, headers);
  res.end(response.body);
}

function writeError(res: nodeHttp.ServerResponse, status: number, message: string, requestId: string): void {
  writeResponse(res, errorResponse(status, message), requestId);
}

/** Parse the command lines of an upload-pack v2 request body. */
function parseUploadPackRequest(body: Buffer): { command: string; args: string[] } {
  const decoded = decodeUntilFlush(body);
  if (decoded === null) throw new Error('upload-pack request has no flush packet');
  const lines: string[] = [];
  for (const packet of decoded.packets) {
    if (packet.kind === 'data') lines.push(packet.payload.toString('utf8').replace(/\n$/, ''));
  }
  if (lines.length === 0) throw new Error('upload-pack request is empty');
  const first = lines[0] as string;
  if (!first.startsWith('command=')) throw new Error('upload-pack request has no command');
  return { command: first.slice('command='.length), args: lines.slice(1) };
}

function handleGitInfoRefs(repo: ForgeRepo, ctx: RequestContext, service: string): ForgeResponse {
  if (service === 'git-upload-pack') {
    const version = headerString(ctx.headers, 'git-protocol');
    if (version === 'version=2') {
      return bufferResponse(200, advertisementV2(repo), 'application/x-git-upload-pack-advertisement');
    }
    return bufferResponse(200, advertisementV0(repo, 'git-upload-pack'), 'application/x-git-upload-pack-advertisement');
  }
  if (service === 'git-receive-pack') {
    return bufferResponse(200, advertisementV0(repo, 'git-receive-pack'), 'application/x-git-receive-pack-advertisement');
  }
  return errorResponse(400, 'Unknown git service');
}

function handleGitUploadPack(repo: ForgeRepo, body: Buffer): ForgeResponse {
  let request: { command: string; args: string[] };
  try {
    request = parseUploadPackRequest(body);
  } catch (error) {
    return errorResponse(400, (error as Error).message);
  }
  const args = request.args.filter((line) => line !== '');
  if (request.command === 'ls-refs') {
    const mutable = {
      prefixes: [] as string[],
      peel: false,
      symrefs: false,
      unborn: false,
    };
    for (const line of args) {
      if (line === 'peel') mutable.peel = true;
      else if (line === 'symrefs') mutable.symrefs = true;
      else if (line === 'unborn') mutable.unborn = true;
      else if (line.startsWith('ref-prefix ')) mutable.prefixes.push(line.slice('ref-prefix '.length));
    }
    const options: LsRefsOptions = mutable;
    return bufferResponse(200, lsRefsV2(repo, options), 'application/x-git-upload-pack-result');
  }
  if (request.command === 'fetch') {
    const wants: string[] = [];
    const haves: string[] = [];
    const shallowBoundaries: string[] = [];
    let depth: number | null = null;
    let filter: string | null = null;
    for (const line of args) {
      if (line.startsWith('want ')) wants.push(line.slice(5));
      else if (line.startsWith('have ')) haves.push(line.slice(5));
      else if (line.startsWith('shallow ')) shallowBoundaries.push(line.slice(8));
      else if (line.startsWith('deepen ')) {
        const parsed = Number.parseInt(line.slice(7), 10);
        if (Number.isFinite(parsed) && parsed > 0) depth = parsed;
      } else if (line.startsWith('filter ')) filter = line.slice(7);
    }
    if (wants.length === 0) return errorResponse(400, 'fetch needs at least one want');
    for (const want of wants) if (!isHex40(want)) return errorResponse(400, 'fetch wants a bad object id');
    const bytes = fetchV2Response(repo, wants, haves, depth, filter, shallowBoundaries);
    return bufferResponse(200, bytes, 'application/x-git-upload-pack-result');
  }
  return errorResponse(400, `Unknown upload-pack command: ${request.command}`);
}

function dispatchRest(ctx: RequestContext): ForgeResponse {
  const segments = ctx.segments;
  // GET /api/v3/ and /api/v3
  if (segments.length <= 2) {
    if (ctx.method === 'GET') return restRoot(ctx);
    return errorResponse(404, 'Not Found');
  }
  if (segments[2] === 'meta') {
    if (ctx.method === 'GET') return restMeta(ctx);
    return errorResponse(404, 'Not Found');
  }
  if (segments[2] === 'user') {
    if (segments.length === 3) {
      if (ctx.method === 'GET') return restGetUser(ctx);
      return errorResponse(404, 'Not Found');
    }
    if (segments[3] === 'repos') {
      if (ctx.method === 'GET') return restListUserRepos(ctx);
      if (ctx.method === 'POST') return restCreateRepo(ctx);
      return errorResponse(404, 'Not Found');
    }
    return errorResponse(404, 'Not Found');
  }
  if (segments[2] === 'repos') {
    if (segments.length < 5) return errorResponse(404, 'Not Found');
    const rest = segments.slice(5);
    if (rest.length === 0) {
      if (ctx.method === 'GET') return restGetRepo(ctx);
      if (ctx.method === 'PATCH') return restPatchRepo(ctx);
      if (ctx.method === 'DELETE') return restDeleteRepo(ctx);
      return errorResponse(404, 'Not Found');
    }
    if (rest[0] === 'branches' && rest.length === 1) {
      if (ctx.method === 'GET') return restListBranches(ctx);
      return errorResponse(404, 'Not Found');
    }
    if (rest[0] === 'commits' && rest.length === 1) {
      if (ctx.method === 'GET') return restListCommits(ctx);
      return errorResponse(404, 'Not Found');
    }
    if (rest[0] === 'git' && rest[1] === 'refs') {
      if (rest.length === 2) {
        if (ctx.method === 'GET') return restListRefs(ctx);
        if (ctx.method === 'POST') return restCreateRef(ctx);
        return errorResponse(404, 'Not Found');
      }
      if (ctx.method === 'GET') return restGetRef(ctx);
      return errorResponse(404, 'Not Found');
    }
    if (rest[0] === 'contents') {
      if (ctx.method === 'GET') return restGetContents(ctx);
      if (ctx.method === 'PUT') return restPutContents(ctx);
      if (ctx.method === 'DELETE') return restDeleteContents(ctx);
      return errorResponse(404, 'Not Found');
    }
    if (rest[0] === 'labels') {
      if (rest.length === 1) {
        if (ctx.method === 'GET') return restListLabels(ctx);
        if (ctx.method === 'POST') return restCreateLabel(ctx);
        return errorResponse(404, 'Not Found');
      }
      if (rest.length === 2) {
        if (ctx.method === 'GET') return restGetLabel(ctx);
        return errorResponse(404, 'Not Found');
      }
      return errorResponse(404, 'Not Found');
    }
    if (rest[0] === 'issues') {
      if (rest.length === 1) {
        if (ctx.method === 'GET') return restListIssues(ctx);
        if (ctx.method === 'POST') return restCreateIssue(ctx);
        return errorResponse(404, 'Not Found');
      }
      if (rest.length === 2) {
        if (ctx.method === 'GET') return restGetIssue(ctx);
        if (ctx.method === 'PATCH') return restPatchIssue(ctx);
        return errorResponse(404, 'Not Found');
      }
      if (rest.length === 3 && rest[2] === 'comments') {
        if (ctx.method === 'GET') return restListComments(ctx);
        if (ctx.method === 'POST') return restCreateComment(ctx);
        return errorResponse(404, 'Not Found');
      }
      return errorResponse(404, 'Not Found');
    }
    if (rest[0] === 'pulls') {
      if (rest.length === 1) {
        if (ctx.method === 'GET') return restListPulls(ctx);
        if (ctx.method === 'POST') return restCreatePull(ctx);
        return errorResponse(404, 'Not Found');
      }
      if (rest.length === 2) {
        if (ctx.method === 'GET') return restGetPull(ctx);
        return errorResponse(404, 'Not Found');
      }
      if (rest.length === 3 && rest[2] === 'files') {
        if (ctx.method === 'GET') return restListPullFiles(ctx);
        return errorResponse(404, 'Not Found');
      }
      if (rest.length === 3 && rest[2] === 'merge') {
        if (ctx.method === 'PUT') return restMergePull(ctx);
        return errorResponse(404, 'Not Found');
      }
      return errorResponse(404, 'Not Found');
    }
    return errorResponse(404, 'Not Found');
  }
  return errorResponse(404, 'Not Found');
}

function dispatch(ctx: RequestContext, body: Buffer): ForgeResponse {
  const segments = ctx.segments;
  // Public: the health check.
  if (segments.length === 1 && segments[0] === 'healthz') {
    if (ctx.method === 'GET') return jsonResponse(200, { status: 'ok' });
    return errorResponse(404, 'Not Found');
  }
  // Everything else needs the shop token.
  if (!isAuthenticated(ctx.headers)) return errorResponse(401, 'Bad credentials');
  // GraphQL.
  if (segments.length === 2 && segments[0] === 'api' && segments[1] === 'graphql') {
    if (ctx.method === 'POST') return restGraphQL(ctx);
    return errorResponse(404, 'Not Found');
  }
  // MCP.
  if (segments.length === 1 && segments[0] === 'mcp') return mcpHandleRequest(ctx);
  // REST v3.
  if (segments.length >= 2 && segments[0] === 'api' && segments[1] === 'v3') return dispatchRest(ctx);
  // Smart HTTP git: /{owner}/{repo}.git/info/refs and /{owner}/{repo}.git/{service}.
  if (segments.length >= 3 && segments[1]?.endsWith('.git')) {
    const owner = decodeSegment(segments[0] as string);
    const repoName = decodeSegment((segments[1] as string).slice(0, -4));
    if (owner !== VIEWER_LOGIN) return errorResponse(404, 'Not Found');
    const repo = lookupRepo(owner, repoName);
    if (repo === undefined) return errorResponse(404, 'Not Found');
    if (segments[2] === 'info' && segments[3] === 'refs' && ctx.method === 'GET') {
      const service = ctx.query.service ?? '';
      return handleGitInfoRefs(repo, ctx, service);
    }
    if (segments[2] === 'git-upload-pack' && ctx.method === 'POST') {
      return handleGitUploadPack(repo, body);
    }
    if (segments[2] === 'git-receive-pack' && ctx.method === 'POST') {
      const bytes = applyReceivePack(repo, body);
      return bufferResponse(200, bytes, 'application/x-git-receive-pack-result');
    }
    return errorResponse(404, 'Not Found');
  }
  return errorResponse(404, 'Not Found');
}

const MAX_BODY_BYTES = 64 * 1024 * 1024;

function serve(): nodeHttp.Server {
  const server = nodeHttp.createServer((req, res) => {
    const requestId = `req-${(requestCounter += 1)}-${randomSuffix()}`;
    const chunks: Buffer[] = [];
    let received = 0;
    let tooLarge = false;
    req.on('data', (chunk: Buffer) => {
      received += chunk.length;
      if (received > MAX_BODY_BYTES) {
        tooLarge = true;
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (tooLarge) {
        writeError(res, 413, 'Request Entity Too Large', requestId);
        return;
      }
      const body = Buffer.concat(chunks);
      let url: URL;
      try {
        const host = req.headers.host ?? 'localhost';
        url = new URL(req.url ?? '/', `http://${host}`);
      } catch {
        writeError(res, 400, 'Bad Request', requestId);
        return;
      }
      const ctx: RequestContext = {
        method: req.method ?? 'GET',
        segments: splitPath(url.pathname),
        query: parseQuery(url.search.slice(1)),
        bodyText: body.toString('utf8'),
        headers: req.headers as Record<string, string | string[] | undefined>,
        baseUrl: `http://${req.headers.host ?? 'localhost'}`,
      };
      try {
        const response = dispatch(ctx, body);
        writeResponse(res, response, requestId);
      } catch (error) {
        process.stderr.write(`[entry] dispatch failed: ${(error as Error).message}\n`);
        writeError(res, 500, (error as Error).message || 'Internal Server Error', requestId);
      }
    });
    req.on('error', () => {
      try {
        writeError(res, 400, 'Bad Request', requestId);
      } catch {
        // The socket is already gone; nothing left to do.
      }
    });
  });
  return server;
}

// ---------------------------------------------------------------------------
// Lifecycle: bind an ephemeral port, register with the env, poll /done, exit
// ---------------------------------------------------------------------------

const REQUEST_TIMEOUT_MS = 30_000;
const RETRY_INITIAL_MS = 250;
const RETRY_MAX_MS = 2_000;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** The wait after `attempt` failed requests: exponential from RETRY_INITIAL_MS, capped. */
function retryDelay(attempt: number): number {
  return Math.min(RETRY_MAX_MS, RETRY_INITIAL_MS * 2 ** Math.min(attempt, 8));
}

/**
 * POST the bound port until the env accepts it. 200 is the normal answer;
 * 409 means a first register already won. 400 and 405 are contract errors
 * and end the program; anything else is retried, since the env may still
 * be starting.
 */
async function registerWithEnv(envUrl: string, port: number): Promise<void> {
  for (let attempt = 0; ; attempt += 1) {
    try {
      const res = await fetch(`${envUrl}/register`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ port }),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
      if (res.status === 200 || res.status === 409) return;
      if (res.status === 400 || res.status === 405) {
        throw new Error(`register answered HTTP ${res.status}: ${await res.text()}`);
      }
    } catch (error) {
      if (error instanceof Error && error.message.startsWith('register answered HTTP ')) throw error;
    }
    await sleep(retryDelay(attempt));
  }
}

/** Poll GET /done until it answers {"done": true}; never return before that. */
async function waitForDone(envUrl: string): Promise<void> {
  for (let attempt = 0; ; attempt += 1) {
    try {
      const res = await fetch(`${envUrl}/done`, { signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
      if (res.ok) {
        const body = (await res.json()) as { done?: unknown };
        if (body.done === true) return;
      }
    } catch {
      // The env is not answering yet, or the poll timed out: not done, poll again.
    }
    await sleep(retryDelay(attempt));
  }
}

/** Bound the port, register it, then wait for the env: the whole life of the process. */
async function main(): Promise<void> {
  const envOrigin = envUrl().replace(/\/+$/, '');
  if (envOrigin === '') {
    process.stderr.write('[entry] MAKEFUN_ENV_URL is not set: there is no env to register with\n');
    process.exit(1);
  }
  const server = serve();
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, () => resolve());
  });
  const address = server.address();
  if (address === null || typeof address === 'string') {
    throw new Error('the server did not bind an ephemeral TCP port');
  }
  process.stdout.write(`[entry] listening on port ${address.port}\n`);
  await registerWithEnv(envOrigin, address.port);
  process.stdout.write('[entry] registered; waiting for the env to say done\n');
  await waitForDone(envOrigin);
  server.close();
  process.stdout.write('[entry] done\n');
}

try {
  await main();
  process.exit(0);
} catch (error) {
  process.stderr.write(`[entry] ${error instanceof Error ? error.message : String(error)}\n`);
  process.exit(1);
}
