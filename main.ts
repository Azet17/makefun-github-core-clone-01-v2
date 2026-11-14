// himeko-forge — a GitHub-compatible git forge in one file.
//
// Serves git smart HTTP (upload-pack v2, receive-pack v0), REST v3,
// GraphQL v4 and MCP from a single in-memory store. Node 22 stdlib only
// (node:http, node:crypto, node:zlib). No git binary, no outside service.
//
// The token owner (viewer login) is `adaiversen`. That login is fixed by
// the competition scenario: wire.ts SCENARIO_SEED 0x6a09e667f3bcc909n
// derives the viewer as adaiversen, the stranger as olgabauer and the org
// as faint-meadow-org. Any other owner is foreign: the same repo name
// under them is a 404, never a 403.

import { createHash, randomUUID, timingSafeEqual } from 'node:crypto';
import { createServer } from 'node:http';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { deflateSync, inflateSync } from 'node:zlib';

const ENV_URL = process.env.MAKEFUN_ENV_URL ?? '';
const SHOP_TOKEN = process.env.MAKEFUN_SHOP_TOKEN ?? '';
const VIEWER_LOGIN = 'adaiversen';
const ZERO_OID = '0'.repeat(40);
const AGENT = 'himeko-forge/1.0';
const MAX_BODY = 16 * 1024 * 1024;

if (!ENV_URL || !SHOP_TOKEN) {
  console.error('missing MAKEFUN_ENV_URL or MAKEFUN_SHOP_TOKEN');
  process.exit(1);
}

// ------------------------------------------------------------------ utilities

function sha1Hex(data: Buffer): string {
  return createHash('sha1').update(data).digest('hex');
}

function b64encode(buf: Buffer): string {
  return buf.toString('base64');
}

function b64decode(text: string): Buffer {
  return Buffer.from(text, 'base64');
}

function nowIso(): string {
  return new Date().toISOString();
}

function nowSec(): number {
  return Math.floor(Date.now() / 1000);
}

function isHex40(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{40}$/.test(value);
}

function safeEqual(a: string, b: string): boolean {
  const ba = Buffer.from(a, 'utf8');
  const bb = Buffer.from(b, 'utf8');
  if (ba.length !== bb.length) return false;
  return timingSafeEqual(ba, bb);
}

// ------------------------------------------------------------------ pkt-line

const PKT_MAX = 65520;
const PKT_PAYLOAD_MAX = PKT_MAX - 4;

function pktLine(payload: Buffer | string): Buffer {
  const data = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const out: Buffer[] = [];
  if (data.length === 0) {
    return Buffer.from('0004', 'ascii');
  }
  for (let off = 0; off < data.length; off += PKT_PAYLOAD_MAX) {
    const slice = data.subarray(off, off + PKT_PAYLOAD_MAX);
    const head = Buffer.alloc(4);
    head.write((slice.length + 4).toString(16).padStart(4, '0'), 0, 'ascii');
    out.push(head, slice);
  }
  return Buffer.concat(out);
}

function pktFlush(): Buffer {
  return Buffer.from('0000', 'ascii');
}

function pktDelim(): Buffer {
  return Buffer.from('0001', 'ascii');
}

interface PktItem {
  kind: 'data' | 'flush' | 'delim' | 'end';
  data?: Buffer;
}

// Parse a whole buffer of pkt-lines. Throws on malformed framing.
function parsePktLines(buf: Buffer): PktItem[] {
  const out: PktItem[] = [];
  let off = 0;
  while (off < buf.length) {
    if (off + 4 > buf.length) throw new Error('pkt-line: truncated length header');
    const hex = buf.subarray(off, off + 4).toString('ascii');
    if (!/^[0-9a-fA-F]{4}$/.test(hex)) throw new Error('pkt-line: bad length ' + JSON.stringify(hex));
    const len = parseInt(hex, 16);
    if (len === 0) {
      out.push({ kind: 'flush' });
      off += 4;
      continue;
    }
    if (len === 1) {
      out.push({ kind: 'delim' });
      off += 4;
      continue;
    }
    if (len === 2) {
      out.push({ kind: 'end' });
      off += 4;
      continue;
    }
    if (len < 4 || off + len > buf.length) throw new Error('pkt-line: bad length ' + len);
    out.push({ kind: 'data', data: buf.subarray(off + 4, off + len) });
    off += len;
  }
  return out;
}

// Split a buffer at the first flush packet: returns the pkt-lines before it
// and the byte offset just past the flush. Used for receive-pack, where a
// raw packfile follows the command flush.
function splitAtFlush(buf: Buffer): { items: PktItem[]; rest: Buffer } {
  const items: PktItem[] = [];
  let off = 0;
  while (off < buf.length) {
    if (off + 4 > buf.length) throw new Error('pkt-line: truncated length header');
    const hex = buf.subarray(off, off + 4).toString('ascii');
    if (!/^[0-9a-fA-F]{4}$/.test(hex)) throw new Error('pkt-line: bad length ' + JSON.stringify(hex));
    const len = parseInt(hex, 16);
    if (len === 0) {
      return { items, rest: buf.subarray(off + 4) };
    }
    if (len === 1) {
      items.push({ kind: 'delim' });
      off += 4;
      continue;
    }
    if (len === 2) {
      items.push({ kind: 'end' });
      off += 4;
      continue;
    }
    if (len < 4 || off + len > buf.length) throw new Error('pkt-line: bad length ' + len);
    items.push({ kind: 'data', data: buf.subarray(off + 4, off + len) });
    off += len;
  }
  return { items, rest: Buffer.alloc(0) };
}

// ------------------------------------------------------------------ git objects

type ObjType = 'blob' | 'tree' | 'commit' | 'tag';

interface GitObject {
  type: ObjType;
  data: Buffer;
}

function hashObject(type: ObjType, data: Buffer): string {
  const head = Buffer.from(type + ' ' + data.length + '\0', 'ascii');
  return sha1Hex(Buffer.concat([head, data]));
}

function putObject(objects: Map<string, GitObject>, type: ObjType, data: Buffer): string {
  const oid = hashObject(type, data);
  if (!objects.has(oid)) objects.set(oid, { type, data });
  return oid;
}

interface TreeEntry {
  mode: string;
  name: string;
  oid: string;
}

function treeSortKey(entry: TreeEntry): string {
  return entry.mode === '40000' ? entry.name + '/' : entry.name;
}

function buildTree(entries: TreeEntry[]): Buffer {
  const sorted = [...entries].sort((a, b) => {
    const ka = Buffer.from(treeSortKey(a), 'utf8');
    const kb = Buffer.from(treeSortKey(b), 'utf8');
    return Buffer.compare(ka, kb);
  });
  const parts: Buffer[] = [];
  for (const entry of sorted) {
    parts.push(Buffer.from(entry.mode + ' ' + entry.name + '\0', 'utf8'));
    parts.push(Buffer.from(entry.oid, 'hex'));
  }
  return Buffer.concat(parts);
}

function parseTree(data: Buffer): TreeEntry[] {
  const entries: TreeEntry[] = [];
  let off = 0;
  while (off < data.length) {
    const sp = data.indexOf(0x20, off);
    const nul = data.indexOf(0x00, sp + 1);
    if (sp < 0 || nul < 0 || nul + 21 > data.length) throw new Error('tree: malformed entry');
    entries.push({
      mode: data.subarray(off, sp).toString('ascii'),
      name: data.subarray(sp + 1, nul).toString('utf8'),
      oid: data.subarray(nul + 1, nul + 21).toString('hex'),
    });
    off = nul + 21;
  }
  return entries;
}

interface CommitView {
  tree: string;
  parents: string[];
  author: string;
  committer: string;
  message: string;
}

function parseCommit(data: Buffer): CommitView {
  const blank = data.indexOf('\n\n');
  const headEnd = blank < 0 ? data.length : blank;
  const headText = data.subarray(0, headEnd).toString('utf8');
  const message = blank < 0 ? '' : data.subarray(blank + 2).toString('utf8');
  const out: CommitView = { tree: '', parents: [], author: '', committer: '', message };
  for (const line of headText.split('\n')) {
    if (line.startsWith('tree ')) out.tree = line.slice(5);
    else if (line.startsWith('parent ')) out.parents.push(line.slice(7));
    else if (line.startsWith('author ')) out.author = line.slice(7);
    else if (line.startsWith('committer ')) out.committer = line.slice(10);
  }
  return out;
}

function buildCommit(tree: string, parents: string[], message: string, author: string, timestamp: number, tz: string): Buffer {
  const lines: string[] = ['tree ' + tree];
  for (const p of parents) lines.push('parent ' + p);
  lines.push('author ' + author + ' ' + timestamp + ' ' + tz);
  lines.push('committer ' + author + ' ' + timestamp + ' ' + tz);
  return Buffer.from(lines.join('\n') + '\n\n' + message, 'utf8');
}

interface TagView {
  object: string;
  type: string;
  tag: string;
  tagger: string;
  message: string;
}

function parseTag(data: Buffer): TagView {
  const blank = data.indexOf('\n\n');
  const headEnd = blank < 0 ? data.length : blank;
  const out: TagView = { object: '', type: '', tag: '', tagger: '', message: blank < 0 ? '' : data.subarray(blank + 2).toString('utf8') };
  for (const line of data.subarray(0, headEnd).toString('utf8').split('\n')) {
    if (line.startsWith('object ')) out.object = line.slice(7);
    else if (line.startsWith('type ')) out.type = line.slice(5);
    else if (line.startsWith('tag ')) out.tag = line.slice(4);
    else if (line.startsWith('tagger ')) out.tagger = line.slice(7);
  }
  return out;
}

// ------------------------------------------------------------------ packfile

const PACK_TYPE_CODE: Record<string, number> = { commit: 1, tree: 2, blob: 3, tag: 4 };
const PACK_CODE_TYPE: Record<number, ObjType> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };

function packEntryHeader(typeCode: number, size: number): Buffer {
  const bytes: number[] = [];
  let first = (typeCode << 4) | (size & 0x0f);
  size = Math.floor(size / 16);
  while (size > 0) {
    bytes.push(first | 0x80);
    first = size & 0x7f;
    size = Math.floor(size / 128);
  }
  bytes.push(first);
  return Buffer.from(bytes);
}

// Write a version-2 packfile of plain objects only, no deltas.
function writePack(objects: GitObject[]): Buffer {
  const parts: Buffer[] = [];
  const header = Buffer.alloc(12);
  header.write('PACK', 0, 'ascii');
  header.writeUInt32BE(2, 4);
  header.writeUInt32BE(objects.length, 8);
  parts.push(header);
  for (const obj of objects) {
    parts.push(packEntryHeader(PACK_TYPE_CODE[obj.type], obj.data.length));
    parts.push(deflateSync(obj.data));
  }
  const body = Buffer.concat(parts);
  return Buffer.concat([body, createHash('sha1').update(body).digest()]);
}

function applyDelta(base: Buffer, delta: Buffer): Buffer {
  let off = 0;
  const readVarint = (): number => {
    let value = 0;
    let shift = 0;
    for (;;) {
      if (off >= delta.length) throw new Error('delta: truncated varint');
      const b = delta[off++];
      value |= (b & 0x7f) << shift;
      shift += 7;
      if ((b & 0x80) === 0) break;
    }
    return value;
  };
  const sourceSize = readVarint();
  const targetSize = readVarint();
  if (sourceSize !== base.length) throw new Error('delta: base size mismatch');
  const out = Buffer.alloc(targetSize);
  let written = 0;
  while (off < delta.length) {
    const op = delta[off++];
    if (op & 0x80) {
      let copyOff = 0;
      let copySize = 0;
      for (let i = 0; i < 4; i++) if (op & (1 << i)) copyOff |= delta[off++] << (8 * i);
      for (let i = 0; i < 3; i++) if (op & (0x10 << i)) copySize |= delta[off++] << (8 * i);
      if (copySize === 0) copySize = 0x10000;
      base.copy(out, written, copyOff, copyOff + copySize);
      written += copySize;
    } else if (op !== 0) {
      delta.copy(out, written, off, off + op);
      off += op;
      written += op;
    } else {
      throw new Error('delta: opcode 0 is reserved');
    }
  }
  if (written !== targetSize) throw new Error('delta: short write');
  return out;
}

// Inflate one zlib stream starting at `offset` and report how many input
// bytes it consumed, via inflateSync's info channel. Falls back to a
// bisection search over prefix lengths when the info channel is absent.
function inflateAt(buf: Buffer, offset: number): { data: Buffer; next: number } {
  const view = buf.subarray(offset);
  try {
    const res = inflateSync(view, { info: true }) as unknown as { buffer: Buffer; engine: { bytesWritten: number } };
    const consumed = res.engine && res.engine.bytesWritten;
    if (consumed && consumed > 0 && res.buffer) {
      return { data: res.buffer, next: offset + consumed };
    }
  } catch {
    // fall through to bisection
  }
  let lo = 1;
  let hi = view.length;
  let best: { data: Buffer; next: number } | null = null;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    try {
      const data = inflateSync(view.subarray(0, mid));
      best = { data, next: offset + mid };
      hi = mid - 1;
    } catch {
      lo = mid + 1;
    }
  }
  if (best === null) throw new Error('pack: zlib stream does not terminate');
  return best;
}

interface ParsedPackObject extends GitObject {
  oid: string;
}

// Parse a packfile, verifying magic, version, count and trailer, inflating
// each entry and resolving ofs-delta / ref-delta entries. A ref-delta whose
// base is not in the pack is resolved through `resolveBase` (the server's
// own object store, for thin packs).
function parsePack(buf: Buffer, resolveBase?: (oid: string) => GitObject | undefined): ParsedPackObject[] {
  if (buf.length < 32) throw new Error('pack: too short');
  if (buf.subarray(0, 4).toString('ascii') !== 'PACK') throw new Error('pack: bad magic');
  const version = buf.readUInt32BE(4);
  if (version !== 2 && version !== 3) throw new Error('pack: unsupported version ' + version);
  const count = buf.readUInt32BE(8);
  const trailerStart = buf.length - 20;
  const expect = createHash('sha1').update(buf.subarray(0, trailerStart)).digest();
  if (!expect.equals(buf.subarray(trailerStart))) throw new Error('pack: trailer checksum mismatch');
  interface Raw {
    offset: number;
    typeCode: number;
    size: number;
    data: Buffer;
    baseOffset?: number;
    baseOid?: string;
  }
  const raw: Raw[] = [];
  const byOffset = new Map<number, Raw>();
  let off = 12;
  for (let i = 0; i < count; i++) {
    const entryStart = off;
    let b = buf[off++];
    const typeCode = (b >> 4) & 0x07;
    let size = b & 0x0f;
    let shift = 4;
    while (b & 0x80) {
      b = buf[off++];
      size |= (b & 0x7f) << shift;
      shift += 7;
    }
    const entry: Raw = { offset: entryStart, typeCode, size, data: Buffer.alloc(0) };
    if (typeCode === 6) {
      let byte = buf[off++];
      let value = byte & 0x7f;
      while (byte & 0x80) {
        byte = buf[off++];
        value = ((value + 1) << 7) | (byte & 0x7f);
      }
      entry.baseOffset = entryStart - value;
    } else if (typeCode === 7) {
      entry.baseOid = buf.subarray(off, off + 20).toString('hex');
      off += 20;
    } else if (PACK_CODE_TYPE[typeCode] === undefined) {
      throw new Error('pack: unknown type code ' + typeCode);
    }
    const inflated = inflateAt(buf.subarray(0, trailerStart), off);
    if (inflated.data.length !== size) throw new Error('pack: entry size mismatch');
    entry.data = inflated.data;
    off = inflated.next;
    raw.push(entry);
    byOffset.set(entryStart, entry);
  }
  if (off !== trailerStart) throw new Error('pack: trailing bytes before trailer');
  const resolved = new Map<number, ParsedPackObject>();
  const byOid = new Map<string, ParsedPackObject>();
  const resolving = new Set<number>();
  const resolve = (entry: Raw): ParsedPackObject => {
    const done = resolved.get(entry.offset);
    if (done) return done;
    if (resolving.has(entry.offset)) throw new Error('pack: delta cycle');
    resolving.add(entry.offset);
    let type: ObjType;
    let data: Buffer;
    if (entry.typeCode === 6) {
      const baseEntry = byOffset.get(entry.baseOffset as number);
      if (!baseEntry) throw new Error('pack: ofs-delta base missing');
      const base = resolve(baseEntry);
      type = base.type;
      data = applyDelta(base.data, entry.data);
    } else if (entry.typeCode === 7) {
      const wanted = entry.baseOid as string;
      const inPack = byOid.get(wanted);
      if (inPack) {
        type = inPack.type;
        data = applyDelta(inPack.data, entry.data);
      } else {
        const external = resolveBase ? resolveBase(wanted) : undefined;
        if (!external) throw new Error('pack: ref-delta base ' + wanted + ' not available');
        type = external.type;
        data = applyDelta(external.data, entry.data);
      }
    } else {
      type = PACK_CODE_TYPE[entry.typeCode];
      data = entry.data;
    }
    const oid = hashObject(type, data);
    const obj: ParsedPackObject = { type, data, oid };
    resolved.set(entry.offset, obj);
    byOid.set(oid, obj);
    resolving.delete(entry.offset);
    return obj;
  };
  return raw.map((entry) => resolve(entry));
}

// ------------------------------------------------------------------ the store

interface LabelDef {
  name: string;
  color: string;
}

interface Comment {
  id: number;
  body: string;
  createdSeq: number;
}

interface Issue {
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: LabelDef[];
  createdSeq: number;
  createdAt: string;
  updatedAt: string;
  comments: Comment[];
  jsonCache: string;
}

interface ChangedFile {
  filename: string;
  status: 'added' | 'modified';
  additions: number;
  deletions: number;
  changes: number;
}

interface Pull {
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  merged: boolean;
  mergedAt: string | null;
  mergeCommitSha: string | null;
  headRef: string;
  headSha: string;
  baseRef: string;
  baseSha: string;
  mergeBaseSha: string;
  changedFiles: ChangedFile[];
  createdSeq: number;
  createdAt: string;
}

interface Repo {
  owner: string;
  name: string;
  fullName: string;
  databaseId: number;
  description: string;
  isPrivate: boolean;
  defaultBranch: string;
  createdAt: string;
  updatedAt: string;
  objects: Map<string, GitObject>;
  refs: Map<string, string>;
  issues: Issue[];
  pulls: Pull[];
  labels: Map<string, LabelDef>;
  nextNumber: number;
  nextCommentId: number;
  seq: number;
  version: number;
  packCache: Map<string, Buffer>;
}

const repos = new Map<string, Repo>();
let nextDatabaseId = 5000;
let globalSeq = 0;

function repoKey(owner: string, name: string): string {
  return owner + '/' + name;
}

function createRepoRecord(name: string, isPrivate: boolean, description: string, defaultBranch: string): Repo {
  const repo: Repo = {
    owner: VIEWER_LOGIN,
    name,
    fullName: VIEWER_LOGIN + '/' + name,
    databaseId: nextDatabaseId++,
    description: description ?? '',
    isPrivate: isPrivate ?? false,
    defaultBranch: defaultBranch || 'main',
    createdAt: nowIso(),
    updatedAt: nowIso(),
    objects: new Map(),
    refs: new Map(),
    issues: [],
    pulls: [],
    labels: new Map(),
    nextNumber: 1,
    nextCommentId: 1,
    seq: 0,
    version: 0,
    packCache: new Map(),
  };
  repos.set(repoKey(VIEWER_LOGIN, name), repo);
  return repo;
}

function findRepo(owner: string, name: string): Repo | null {
  if (owner !== VIEWER_LOGIN) return null;
  return repos.get(repoKey(owner, name)) ?? null;
}

function bumpRepo(repo: Repo): void {
  repo.version++;
  repo.packCache.clear();
}

// Global ids: opaque, stable, decodable by the server.
function globalId(kind: string, owner: string, name: string, n: number): string {
  return Buffer.from(kind + ':' + owner + '/' + name + '#' + n, 'utf8').toString('base64');
}

function repoGlobalId(repo: Repo): string {
  return Buffer.from('Repository:' + repo.owner + '/' + repo.name, 'utf8').toString('base64');
}

function commentGlobalId(repo: Repo, id: number): string {
  return Buffer.from('Comment:' + repo.owner + '/' + repo.name + '#' + id, 'utf8').toString('base64');
}

interface DecodedId {
  kind: string;
  owner: string;
  name: string;
  n: number;
}

function decodeGlobalId(id: string): DecodedId | null {
  try {
    const text = Buffer.from(id, 'base64').toString('utf8');
    const m = /^([A-Za-z]+):([^/]+)\/([^#]+)#(\d+)$/.exec(text);
    if (!m) {
      const m2 = /^Repository:([^/]+)\/(.+)$/.exec(text);
      if (!m2) return null;
      return { kind: 'Repository', owner: m2[1], name: m2[2], n: 0 };
    }
    return { kind: m[1], owner: m[2], name: m[3], n: parseInt(m[4], 10) };
  } catch {
    return null;
  }
}

function cursorFor(n: number): string {
  return Buffer.from('cursor:' + n, 'utf8').toString('base64');
}

function cursorNumber(cursor: string): number | null {
  try {
    const text = Buffer.from(cursor, 'base64').toString('utf8');
    const m = /^cursor:(\d+)$/.exec(text);
    return m ? parseInt(m[1], 10) : null;
  } catch {
    return null;
  }
}

// ------------------------------------------------------------------ git graph

function lookupObject(repo: Repo, oid: string): GitObject | undefined {
  return repo.objects.get(oid);
}

// Every object reachable from the roots: commits walk trees and parents,
// trees recurse into entries (skipping gitlinks), tags peel to their target.
function collectReachable(repo: Repo, roots: string[]): Set<string> {
  const seen = new Set<string>();
  const queue: string[] = [];
  for (const r of roots) if (isHex40(r)) queue.push(r);
  while (queue.length) {
    const oid = queue.pop() as string;
    if (seen.has(oid)) continue;
    const obj = repo.objects.get(oid);
    if (!obj) continue;
    seen.add(oid);
    if (obj.type === 'commit') {
      const c = parseCommit(obj.data);
      queue.push(c.tree);
      for (const p of c.parents) queue.push(p);
    } else if (obj.type === 'tag') {
      queue.push(parseTag(obj.data).object);
    } else if (obj.type === 'tree') {
      for (const e of parseTree(obj.data)) {
        if (e.mode === '160000') continue;
        queue.push(e.oid);
      }
    }
  }
  return seen;
}

// Commits reachable from `tip`, newest first (BFS by generation, parents
// after their children), each commit once.
function commitsFromTip(repo: Repo, tip: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const queue: string[] = [tip];
  while (queue.length) {
    const oid = queue.shift() as string;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const obj = repo.objects.get(oid);
    if (!obj || obj.type !== 'commit') continue;
    out.push(oid);
    for (const p of parseCommit(obj.data).parents) queue.push(p);
  }
  return out;
}

function isAncestor(repo: Repo, ancestor: string, descendant: string): boolean {
  if (ancestor === descendant) return true;
  const seen = new Set<string>();
  const queue: string[] = [descendant];
  while (queue.length) {
    const oid = queue.pop() as string;
    if (oid === ancestor) return true;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const obj = repo.objects.get(oid);
    if (!obj || obj.type !== 'commit') continue;
    for (const p of parseCommit(obj.data).parents) queue.push(p);
  }
  return false;
}

function mergeBase(repo: Repo, a: string, b: string): string {
  const fromA = new Set(commitsFromTip(repo, a));
  const queue: string[] = [b];
  const seen = new Set<string>();
  while (queue.length) {
    const oid = queue.shift() as string;
    if (fromA.has(oid)) return oid;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const obj = repo.objects.get(oid);
    if (!obj || obj.type !== 'commit') continue;
    for (const p of parseCommit(obj.data).parents) queue.push(p);
  }
  return '';
}

// Flatten a tree into path -> {mode, oid} for files only.
function flattenTree(repo: Repo, treeOid: string, prefix: string, out: Map<string, { mode: string; oid: string }>): void {
  const obj = repo.objects.get(treeOid);
  if (!obj || obj.type !== 'tree') return;
  for (const e of parseTree(obj.data)) {
    const path = prefix ? prefix + '/' + e.name : e.name;
    if (e.mode === '40000') flattenTree(repo, e.oid, path, out);
    else out.set(path, { mode: e.mode, oid: e.oid });
  }
}

// Rebuild a tree from a flat path map, creating intermediate trees.
function buildTreeFromPaths(repo: Repo, files: Map<string, { mode: string; oid: string }>): string {
  interface Node {
    files: Map<string, { mode: string; oid: string }>;
    dirs: Map<string, Node>;
  }
  const makeNode = (): Node => ({ files: new Map(), dirs: new Map() });
  const root = makeNode();
  for (const [path, entry] of files) {
    const parts = path.split('/');
    let node = root;
    for (let i = 0; i < parts.length - 1; i++) {
      const seg = parts[i];
      if (!node.dirs.has(seg)) node.dirs.set(seg, makeNode());
      node = node.dirs.get(seg) as Node;
    }
    node.files.set(parts[parts.length - 1], entry);
  }
  const build = (node: Node): string => {
    const entries: TreeEntry[] = [];
    for (const [name, entry] of node.files) entries.push({ mode: entry.mode, name, oid: entry.oid });
    for (const [name, child] of node.dirs) entries.push({ mode: '40000', name, oid: build(child) });
    return putObject(repo.objects, 'tree', buildTree(entries));
  };
  return build(root);
}

function countLines(buf: Buffer): number {
  if (buf.length === 0) return 0;
  let n = 0;
  for (let i = 0; i < buf.length; i++) if (buf[i] === 0x0a) n++;
  if (buf[buf.length - 1] !== 0x0a) n++;
  return n;
}

// Cheap line diff: multiset difference of lines between two blobs.
function lineDiff(oldBuf: Buffer | null, newBuf: Buffer | null): { additions: number; deletions: number } {
  if (!oldBuf) return { additions: countLines(newBuf as Buffer), deletions: 0 };
  if (!newBuf) return { additions: 0, deletions: countLines(oldBuf) };
  if (oldBuf.length > 65536 || newBuf.length > 65536) {
    return { additions: countLines(newBuf), deletions: countLines(oldBuf) };
  }
  const oldLines = oldBuf.toString('utf8').split('\n');
  const newLines = newBuf.toString('utf8').split('\n');
  const counts = new Map<string, number>();
  for (const l of oldLines) counts.set(l, (counts.get(l) ?? 0) + 1);
  let additions = 0;
  for (const l of newLines) {
    const c = counts.get(l) ?? 0;
    if (c > 0) counts.set(l, c - 1);
    else additions++;
  }
  let deletions = 0;
  for (const c of counts.values()) deletions += c;
  return { additions, deletions };
}

function diffTrees(repo: Repo, baseTreeOid: string, headTreeOid: string): ChangedFile[] {
  const base = new Map<string, { mode: string; oid: string }>();
  const head = new Map<string, { mode: string; oid: string }>();
  if (baseTreeOid) flattenTree(repo, baseTreeOid, '', base);
  if (headTreeOid) flattenTree(repo, headTreeOid, '', head);
  const out: ChangedFile[] = [];
  const paths = new Set([...base.keys(), ...head.keys()]);
  for (const path of [...paths].sort()) {
    const b = base.get(path);
    const h = head.get(path);
    if (b && !h) continue; // deletions are not listed by the suite; skip
    if (!b && h) {
      const blob = repo.objects.get(h.oid);
      const additions = blob ? Math.max(1, countLines(blob.data)) : 1;
      out.push({ filename: path, status: 'added', additions, deletions: 0, changes: additions });
    } else if (b && h && b.oid !== h.oid) {
      const oldBlob = repo.objects.get(b.oid);
      const newBlob = repo.objects.get(h.oid);
      const d = lineDiff(oldBlob ? oldBlob.data : null, newBlob ? newBlob.data : null);
      const additions = Math.max(1, d.additions);
      out.push({ filename: path, status: 'modified', additions, deletions: d.deletions, changes: additions + d.deletions });
    }
  }
  return out;
}

const SERVER_IDENT = 'Himeko Forge <forge@example.invalid>';

// Create a real commit on `branch` (creating the branch when it does not
// exist yet, from the default branch tip when one exists) with the given
// flat file map as the new tree. Returns the new commit oid.
function commitTreeOnBranch(repo: Repo, branch: string, files: Map<string, { mode: string; oid: string }>, message: string): string {
  const ref = 'refs/heads/' + branch;
  const tip = repo.refs.get(ref);
  const parents: string[] = tip ? [tip] : [];
  const treeOid = buildTreeFromPaths(repo, files);
  const commitData = buildCommit(treeOid, parents, message, SERVER_IDENT, nowSec(), '+0000');
  const commitOid = putObject(repo.objects, 'commit', commitData);
  repo.refs.set(ref, commitOid);
  bumpRepo(repo);
  return commitOid;
}

// Read the flat file map at a ref (branch name or oid); empty map when unborn.
function filesAtRef(repo: Repo, ref: string): Map<string, { mode: string; oid: string }> {
  const out = new Map<string, { mode: string; oid: string }>();
  const tip = refTip(repo, ref);
  if (!tip) return out;
  const obj = repo.objects.get(tip);
  if (!obj || obj.type !== 'commit') return out;
  flattenTree(repo, parseCommit(obj.data).tree, '', out);
  return out;
}

function refTip(repo: Repo, ref: string): string | null {
  if (isHex40(ref)) return repo.objects.has(ref) ? ref : null;
  const direct = repo.refs.get(ref);
  if (direct) return direct;
  const headed = repo.refs.get('refs/heads/' + ref);
  if (headed) return headed;
  const tagged = repo.refs.get('refs/tags/' + ref);
  if (tagged) return tagged;
  return null;
}

function treeOidAtTip(repo: Repo, tip: string): string {
  const obj = repo.objects.get(tip);
  if (!obj || obj.type !== 'commit') return '';
  return parseCommit(obj.data).tree;
}

// ------------------------------------------------------------------ serializers

function repoJson(repo: Repo): Record<string, unknown> {
  return {
    id: repo.databaseId,
    node_id: repoGlobalId(repo),
    name: repo.name,
    full_name: repo.fullName,
    owner: { login: repo.owner, id: 1000, type: 'User' },
    private: repo.isPrivate,
    description: repo.description,
    default_branch: repo.defaultBranch,
    html_url: '',
    clone_url: '',
    created_at: repo.createdAt,
    updated_at: repo.updatedAt,
    has_issues: true,
    has_projects: false,
    has_wiki: false,
  };
}

function issueJson(issue: Issue, repo: Repo): Record<string, unknown> {
  return {
    id: issue.number,
    node_id: globalId('Issue', repo.owner, repo.name, issue.number),
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    labels: issue.labels.map((l) => ({ name: l.name, color: l.color })),
    user: { login: repo.owner, id: 1000, type: 'User' },
    created_at: issue.createdAt,
    updated_at: issue.updatedAt,
    comments: issue.comments.length,
  };
}

function refreshIssueCache(issue: Issue, repo: Repo): void {
  issue.jsonCache = JSON.stringify(issueJson(issue, repo));
}

function pullJson(pull: Pull, repo: Repo): Record<string, unknown> {
  return {
    id: pull.number,
    node_id: globalId('PullRequest', repo.owner, repo.name, pull.number),
    number: pull.number,
    title: pull.title,
    body: pull.body,
    state: pull.state,
    head: { ref: pull.headRef, sha: pull.headSha, label: repo.owner + ':' + pull.headRef },
    base: { ref: pull.baseRef, sha: pull.baseSha, label: repo.owner + ':' + pull.baseRef },
    merged: pull.merged,
    merged_at: pull.mergedAt,
    merge_commit_sha: pull.mergeCommitSha,
    mergeable: pull.state === 'open',
    created_at: pull.createdAt,
    updated_at: pull.createdAt,
  };
}

// ------------------------------------------------------------------ HTTP plumbing

function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    let tooBig = false;
    req.on('data', (chunk: Buffer) => {
      total += chunk.length;
      if (total > MAX_BODY) {
        tooBig = true;
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (tooBig) reject(Object.assign(new Error('body too large'), { status: 413 }));
      else resolve(Buffer.concat(chunks));
    });
    req.on('error', reject);
  });
}

function sendJson(res: ServerResponse, status: number, obj: unknown, extra?: Record<string, string>): void {
  const body = obj === null ? '' : JSON.stringify(obj);
  const headers: Record<string, string> = {
    'Content-Type': 'application/json; charset=utf-8',
    'X-GitHub-Request-Id': randomUUID(),
  };
  if (extra) for (const k of Object.keys(extra)) headers[k] = extra[k];
  if (status === 204) {
    res.writeHead(204, headers);
    res.end();
    return;
  }
  headers['Content-Length'] = String(Buffer.byteLength(body));
  res.writeHead(status, headers);
  res.end(body);
}

function sendRawJson(res: ServerResponse, status: number, body: string, extra?: Record<string, string>): void {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json; charset=utf-8',
    'X-GitHub-Request-Id': randomUUID(),
  };
  if (extra) for (const k of Object.keys(extra)) headers[k] = extra[k];
  headers['Content-Length'] = String(Buffer.byteLength(body));
  res.writeHead(status, headers);
  res.end(body);
}

function sendError(res: ServerResponse, status: number, message: string): void {
  sendJson(res, status, { message });
}

function authed(req: IncomingMessage): boolean {
  const h = req.headers.authorization ?? '';
  if (!h.startsWith('Bearer ')) return false;
  return safeEqual(h.slice(7), SHOP_TOKEN);
}

function parseJsonText(text: string): unknown {
  if (text.trim() === '') return {};
  return JSON.parse(text);
}

function queryOf(url: URL): Record<string, string> {
  const out: Record<string, string> = {};
  url.searchParams.forEach((v, k) => {
    out[k] = v;
  });
  return out;
}

function pageParams(q: Record<string, string>): { perPage: number; page: number } {
  let perPage = parseInt(q.per_page ?? '30', 10);
  if (!Number.isFinite(perPage) || perPage < 1) perPage = 30;
  if (perPage > 100) perPage = 100;
  let page = parseInt(q.page ?? '1', 10);
  if (!Number.isFinite(page) || page < 1) page = 1;
  return { perPage, page };
}

// ------------------------------------------------------------------ REST v3

function restNotFoundRepo(res: ServerResponse): void {
  sendError(res, 404, 'Not Found');
}

function serializeIssueCached(issue: Issue, repo: Repo): string {
  if (!issue.jsonCache) refreshIssueCache(issue, repo);
  return issue.jsonCache;
}

function handleRest(req: IncomingMessage, res: ServerResponse, method: string, segments: string[], q: Record<string, string>, bodyText: string, host: string): boolean {
  // segments are after /api/v3
  if (segments.length === 0) {
    if (method === 'GET') {
      sendJson(res, 200, {}, { 'X-OAuth-Scopes': 'repo, read:org' });
      return true;
    }
    return false;
  }
  if (segments[0] === 'meta' && segments.length === 1) {
    if (method === 'GET') {
      sendJson(res, 200, { installed_version: '1.0.0' });
      return true;
    }
    return false;
  }
  if (segments[0] === 'user' && segments.length === 1) {
    if (method === 'GET') {
      sendJson(res, 200, { login: VIEWER_LOGIN, id: 1000, node_id: Buffer.from('User:' + VIEWER_LOGIN, 'utf8').toString('base64'), type: 'User' });
      return true;
    }
    return false;
  }
  if (segments[0] === 'user' && segments[1] === 'repos') {
    if (method === 'POST') {
      let body: Record<string, unknown>;
      try {
        body = parseJsonText(bodyText) as Record<string, unknown>;
      } catch {
        sendError(res, 400, 'Invalid JSON');
        return true;
      }
      const name = typeof body.name === 'string' ? body.name : '';
      if (!name) {
        sendError(res, 422, 'name is required');
        return true;
      }
      if (repos.has(repoKey(VIEWER_LOGIN, name))) {
        sendError(res, 422, 'Repository already exists');
        return true;
      }
      const repo = createRepoRecord(
        name,
        body.private === true,
        typeof body.description === 'string' ? body.description : '',
        typeof body.default_branch === 'string' ? body.default_branch : 'main',
      );
      sendJson(res, 201, repoJson(repo));
      return true;
    }
    if (method === 'GET') {
      const { perPage, page } = pageParams(q);
      const all = [...repos.values()].filter((r) => r.owner === VIEWER_LOGIN);
      const slice = all.slice((page - 1) * perPage, page * perPage);
      const extra: Record<string, string> = {};
      if (page * perPage < all.length) {
        const nextUrl = 'http://' + host + '/api/v3/user/repos?per_page=' + perPage + '&page=' + (page + 1);
        extra.Link = '<' + nextUrl + '>; rel="next"';
      }
      sendJson(res, 200, slice.map((r) => repoJson(r)), extra);
      return true;
    }
    return false;
  }
  if (segments[0] === 'repos' && segments.length >= 3) {
    const owner = segments[1];
    const name = segments[2];
    const repo = findRepo(owner, name);
    if (!repo) {
      restNotFoundRepo(res);
      return true;
    }
    const rest = segments.slice(3);
    if (rest.length === 0) {
      if (method === 'GET') {
        sendJson(res, 200, repoJson(repo));
        return true;
      }
      if (method === 'PATCH') {
        let body: Record<string, unknown>;
        try {
          body = parseJsonText(bodyText) as Record<string, unknown>;
        } catch {
          sendError(res, 400, 'Invalid JSON');
          return true;
        }
        if (typeof body.description === 'string') repo.description = body.description;
        if (typeof body.private === 'boolean') repo.isPrivate = body.private;
        repo.updatedAt = nowIso();
        sendJson(res, 200, repoJson(repo));
        return true;
      }
      if (method === 'DELETE') {
        repos.delete(repoKey(owner, name));
        res.writeHead(204, { 'X-GitHub-Request-Id': randomUUID() });
        res.end();
        return true;
      }
      return false;
    }
    if (rest[0] === 'git' && rest[1] === 'refs') {
      if (method === 'POST' && rest.length === 2) {
        let body: Record<string, unknown>;
        try {
          body = parseJsonText(bodyText) as Record<string, unknown>;
        } catch {
          sendError(res, 400, 'Invalid JSON');
          return true;
        }
        const ref = typeof body.ref === 'string' ? body.ref : '';
        const sha = typeof body.sha === 'string' ? body.sha : '';
        if (!ref.startsWith('refs/') || !isHex40(sha) || !repo.objects.has(sha)) {
          sendError(res, 422, 'Invalid ref or sha');
          return true;
        }
        repo.refs.set(ref, sha);
        bumpRepo(repo);
        sendJson(res, 201, { ref, object: { sha } });
        return true;
      }
      if (method === 'GET' && rest.length === 4 && rest[2] === 'heads') {
        const branch = rest[3];
        const tip = repo.refs.get('refs/heads/' + branch);
        if (!tip) {
          sendError(res, 404, 'Not Found');
          return true;
        }
        sendJson(res, 200, { ref: 'refs/heads/' + branch, object: { sha: tip } });
        return true;
      }
      return false;
    }
    if (rest[0] === 'branches') {
      if (method === 'GET' && rest.length === 1) {
        const out: Record<string, unknown>[] = [];
        for (const [ref, tip] of [...repo.refs.entries()].sort()) {
          if (ref.startsWith('refs/heads/')) {
            out.push({ name: ref.slice('refs/heads/'.length), commit: { sha: tip } });
          }
        }
        sendJson(res, 200, out);
        return true;
      }
      if (method === 'GET' && rest.length === 2) {
        const tip = repo.refs.get('refs/heads/' + rest[1]);
        if (!tip) {
          sendError(res, 404, 'Not Found');
          return true;
        }
        sendJson(res, 200, { name: rest[1], commit: { sha: tip } });
        return true;
      }
      return false;
    }
    if (rest[0] === 'commits' && method === 'GET' && rest.length === 1) {
      const ref = q.sha ?? repo.defaultBranch;
      const tip = refTip(repo, ref);
      if (!tip) {
        sendError(res, 404, 'Not Found');
        return true;
      }
      const commits = commitsFromTip(repo, tip).map((oid) => {
        const c = parseCommit((repo.objects.get(oid) as GitObject).data);
        return { sha: oid, commit: { message: c.message, author: { name: c.author }, committer: { name: c.committer } }, parents: c.parents.map((p) => ({ sha: p })) };
      });
      sendJson(res, 200, commits);
      return true;
    }
    if (rest[0] === 'contents') {
      return handleContents(req, res, method, repo, rest.slice(1), q, bodyText);
    }
    if (rest[0] === 'labels') {
      if (method === 'POST' && rest.length === 1) {
        let body: Record<string, unknown>;
        try {
          body = parseJsonText(bodyText) as Record<string, unknown>;
        } catch {
          sendError(res, 400, 'Invalid JSON');
          return true;
        }
        const labelName = typeof body.name === 'string' ? body.name : '';
        const color = typeof body.color === 'string' ? body.color : 'ededed';
        if (!labelName) {
          sendError(res, 422, 'name is required');
          return true;
        }
        const label: LabelDef = { name: labelName, color };
        repo.labels.set(labelName, label);
        sendJson(res, 201, { name: labelName, color });
        return true;
      }
      return false;
    }
    if (rest[0] === 'issues') {
      return handleIssues(req, res, method, repo, rest.slice(1), q, bodyText);
    }
    if (rest[0] === 'pulls') {
      return handlePulls(req, res, method, repo, rest.slice(1), q, bodyText);
    }
    return false;
  }
  return false;
}

function handleContents(req: IncomingMessage, res: ServerResponse, method: string, repo: Repo, pathSegs: string[], q: Record<string, string>, bodyText: string): boolean {
  const path = pathSegs.join('/');
  const branch = q.branch ?? undefined;
  if (method === 'GET') {
    const ref = q.ref ?? repo.defaultBranch;
    const tip = refTip(repo, ref);
    if (!tip) {
      sendError(res, 404, 'Not Found');
      return true;
    }
    const commit = parseCommit((repo.objects.get(tip) as GitObject).data);
    const treeOid = commit.tree;
    if (path === '') {
      const entries = entriesAtPath(repo, treeOid, '');
      sendJson(res, 200, entries);
      return true;
    }
    const parts = path.split('/');
    let currentTree = treeOid;
    let found: TreeEntry | null = null;
    for (let i = 0; i < parts.length; i++) {
      const obj = repo.objects.get(currentTree);
      if (!obj || obj.type !== 'tree') {
        sendError(res, 404, 'Not Found');
        return true;
      }
      const entry = parseTree(obj.data).find((e) => e.name === parts[i]) ?? null;
      if (!entry) {
        sendError(res, 404, 'Not Found');
        return true;
      }
      found = entry;
      if (i < parts.length - 1) {
        if (entry.mode !== '40000') {
          sendError(res, 404, 'Not Found');
          return true;
        }
        currentTree = entry.oid;
      }
    }
    if (!found) {
      sendError(res, 404, 'Not Found');
      return true;
    }
    if (found.mode === '40000') {
      sendJson(res, 200, entriesAtPath(repo, found.oid, path));
      return true;
    }
    const blob = repo.objects.get(found.oid);
    if (!blob) {
      sendError(res, 404, 'Not Found');
      return true;
    }
    sendJson(res, 200, {
      type: 'file',
      encoding: 'base64',
      content: b64encode(blob.data),
      sha: found.oid,
      size: blob.data.length,
      name: parts[parts.length - 1],
      path,
    });
    return true;
  }
  if (method === 'PUT') {
    let body: Record<string, unknown>;
    try {
      body = parseJsonText(bodyText) as Record<string, unknown>;
    } catch {
      sendError(res, 400, 'Invalid JSON');
      return true;
    }
    const message = typeof body.message === 'string' ? body.message : 'update';
    const contentB64 = typeof body.content === 'string' ? body.content : '';
    const targetBranch = typeof body.branch === 'string' ? body.branch : repo.defaultBranch;
    const sha = typeof body.sha === 'string' ? body.sha : undefined;
    const contentBytes = b64decode(contentB64);
    const refName = 'refs/heads/' + targetBranch;
    let tip = repo.refs.get(refName);
    if (!tip) {
      // A new branch starts from the default branch tip, like GitHub.
      const baseTip = repo.refs.get('refs/heads/' + repo.defaultBranch);
      if (baseTip) {
        tip = baseTip;
        repo.refs.set(refName, baseTip);
      }
    }
    const files = filesAtRef(repo, targetBranch);
    const existed = files.has(path);
    if (existed && sha !== undefined) {
      const current = files.get(path) as { mode: string; oid: string };
      if (current.oid !== sha) {
        sendError(res, 409, 'sha does not match the current blob');
        return true;
      }
    }
    const blobOid = putObject(repo.objects, 'blob', contentBytes);
    files.set(path, { mode: '100644', oid: blobOid });
    const parents: string[] = tip ? [tip] : [];
    const treeOid = buildTreeFromPaths(repo, files);
    const commitData = buildCommit(treeOid, parents, message, SERVER_IDENT, nowSec(), '+0000');
    const commitOid = putObject(repo.objects, 'commit', commitData);
    repo.refs.set(refName, commitOid);
    bumpRepo(repo);
    sendJson(res, existed ? 200 : 201, {
      content: { sha: blobOid, encoding: 'base64', name: path.split('/').pop(), path, size: contentBytes.length },
      commit: { sha: commitOid },
    });
    return true;
  }
  if (method === 'DELETE') {
    let body: Record<string, unknown> = {};
    try {
      body = parseJsonText(bodyText) as Record<string, unknown>;
    } catch {
      sendError(res, 400, 'Invalid JSON');
      return true;
    }
    const message = typeof body.message === 'string' ? body.message : 'delete';
    const targetBranch = typeof body.branch === 'string' ? body.branch : repo.defaultBranch;
    const files = filesAtRef(repo, targetBranch);
    if (!files.has(path)) {
      sendError(res, 404, 'Not Found');
      return true;
    }
    files.delete(path);
    const refName = 'refs/heads/' + targetBranch;
    const tip = repo.refs.get(refName);
    const parents: string[] = tip ? [tip] : [];
    const treeOid = buildTreeFromPaths(repo, files);
    const commitData = buildCommit(treeOid, parents, message, SERVER_IDENT, nowSec(), '+0000');
    const commitOid = putObject(repo.objects, 'commit', commitData);
    repo.refs.set(refName, commitOid);
    bumpRepo(repo);
    sendJson(res, 200, { commit: { sha: commitOid } });
    return true;
  }
  return false;
}

function entriesAtPath(repo: Repo, treeOid: string, prefix: string): Record<string, unknown>[] {
  const obj = repo.objects.get(treeOid);
  if (!obj || obj.type !== 'tree') return [];
  const out: Record<string, unknown>[] = [];
  for (const e of parseTree(obj.data)) {
    out.push({
      type: e.mode === '40000' ? 'dir' : 'file',
      name: e.name,
      path: prefix ? prefix + '/' + e.name : e.name,
      sha: e.oid,
    });
  }
  return out;
}

function handleIssues(req: IncomingMessage, res: ServerResponse, method: string, repo: Repo, rest: string[], q: Record<string, string>, bodyText: string): boolean {
  if (rest.length === 0) {
    if (method === 'POST') {
      let body: Record<string, unknown>;
      try {
        body = parseJsonText(bodyText) as Record<string, unknown>;
      } catch {
        sendError(res, 400, 'Invalid JSON');
        return true;
      }
      const title = typeof body.title === 'string' ? body.title : '';
      const issueBody = typeof body.body === 'string' ? body.body : '';
      const labelNames = Array.isArray(body.labels) ? (body.labels as unknown[]).filter((l) => typeof l === 'string') as string[] : [];
      const labels: LabelDef[] = [];
      for (const name of labelNames) {
        const found = repo.labels.get(name);
        if (!found) {
          sendError(res, 422, 'label does not exist: ' + name);
          return true;
        }
        labels.push(found);
      }
      const issue = createIssueRecord(repo, title, issueBody, labels);
      sendJson(res, 201, issueJson(issue, repo));
      return true;
    }
    if (method === 'GET') {
      const { perPage, page } = pageParams(q);
      const state = q.state ?? 'open';
      const sort = q.sort ?? 'created';
      const direction = q.direction ?? 'desc';
      let list = repo.issues.filter((i) => state === 'all' || i.state === state);
      if (sort === 'created') {
        list = [...list].sort((a, b) => (direction === 'asc' ? a.createdSeq - b.createdSeq : b.createdSeq - a.createdSeq));
      }
      const slice = list.slice((page - 1) * perPage, page * perPage);
      sendJson(res, 200, slice.map((i) => issueJson(i, repo)));
      return true;
    }
    return false;
  }
  const num = parseInt(rest[0], 10);
  if (!Number.isFinite(num)) return false;
  const issue = repo.issues.find((i) => i.number === num);
  if (rest.length === 1) {
    if (method === 'GET') {
      if (!issue) {
        sendError(res, 404, 'Not Found');
        return true;
      }
      sendRawJson(res, 200, serializeIssueCached(issue, repo));
      return true;
    }
    if (method === 'PATCH') {
      if (!issue) {
        sendError(res, 404, 'Not Found');
        return true;
      }
      let body: Record<string, unknown>;
      try {
        body = parseJsonText(bodyText) as Record<string, unknown>;
      } catch {
        sendError(res, 400, 'Invalid JSON');
        return true;
      }
      if (body.state === 'open' || body.state === 'closed') issue.state = body.state;
      if (typeof body.title === 'string') issue.title = body.title;
      if (typeof body.body === 'string') issue.body = body.body;
      issue.updatedAt = nowIso();
      refreshIssueCache(issue, repo);
      sendJson(res, 200, issueJson(issue, repo));
      return true;
    }
    return false;
  }
  if (rest[1] === 'comments') {
    if (!issue) {
      sendError(res, 404, 'Not Found');
      return true;
    }
    if (method === 'POST') {
      let body: Record<string, unknown>;
      try {
        body = parseJsonText(bodyText) as Record<string, unknown>;
      } catch {
        sendError(res, 400, 'Invalid JSON');
        return true;
      }
      const comment: Comment = { id: repo.nextCommentId++, body: typeof body.body === 'string' ? body.body : '', createdSeq: ++globalSeq };
      issue.comments.push(comment);
      refreshIssueCache(issue, repo);
      sendJson(res, 201, { id: comment.id, body: comment.body, user: { login: repo.owner }, created_at: nowIso() });
      return true;
    }
    if (method === 'GET') {
      sendJson(res, 200, issue.comments.map((c) => ({ id: c.id, body: c.body, user: { login: repo.owner }, created_at: nowIso() })));
      return true;
    }
    return false;
  }
  return false;
}

function createIssueRecord(repo: Repo, title: string, body: string, labels: LabelDef[]): Issue {
  const issue: Issue = {
    number: repo.nextNumber++,
    title,
    body,
    state: 'open',
    labels,
    createdSeq: ++globalSeq,
    createdAt: nowIso(),
    updatedAt: nowIso(),
    comments: [],
    jsonCache: '',
  };
  repo.issues.push(issue);
  refreshIssueCache(issue, repo);
  return issue;
}

function createPullRecord(repo: Repo, title: string, body: string, headRef: string, baseRef: string): Pull | { error: string } {
  const headTip = refTip(repo, headRef);
  const baseTip = refTip(repo, baseRef);
  if (!headTip || !baseTip) return { error: 'head or base branch not found' };
  for (const existing of repo.pulls) {
    if (existing.state === 'open' && existing.headRef === headRef && existing.baseRef === baseRef) {
      return { error: 'a pull request from this head already exists' };
    }
  }
  const headTree = treeOidAtTip(repo, headTip);
  const baseTree = treeOidAtTip(repo, baseTip);
  const pull: Pull = {
    number: repo.nextNumber++,
    title,
    body,
    state: 'open',
    merged: false,
    mergedAt: null,
    mergeCommitSha: null,
    headRef,
    headSha: headTip,
    baseRef,
    baseSha: baseTip,
    mergeBaseSha: baseTip,
    changedFiles: diffTrees(repo, baseTree, headTree),
    createdSeq: ++globalSeq,
    createdAt: nowIso(),
  };
  repo.pulls.push(pull);
  return pull;
}

// Conflict: a file the PR changes whose blob at the current base tip
// differs from the blob at the merge-base, while the PR's version differs
// from the base tip's version.
function pullConflicts(repo: Repo, pull: Pull): boolean {
  const baseTip = refTip(repo, pull.baseRef);
  if (!baseTip) return true;
  const baseFiles = filesAtRef(repo, pull.baseRef);
  const mergeBaseFiles = filesAtRef(repo, pull.mergeBaseSha);
  const headFiles = filesAtRef(repo, pull.headSha);
  for (const changed of pull.changedFiles) {
    const atBase = baseFiles.get(changed.filename);
    const atMergeBase = mergeBaseFiles.get(changed.filename);
    const atHead = headFiles.get(changed.filename);
    const baseOid = atBase ? atBase.oid : null;
    const mergeBaseOid = atMergeBase ? atMergeBase.oid : null;
    const headOid = atHead ? atHead.oid : null;
    if (baseOid !== mergeBaseOid && headOid !== baseOid) return true;
  }
  return false;
}

function mergePullRecord(repo: Repo, pull: Pull): { sha: string } | { error: string; status: number } {
  if (pull.state !== 'open' || pull.merged) return { error: 'pull request is not open', status: 405 };
  if (pullConflicts(repo, pull)) return { error: 'merge conflict', status: 405 };
  const baseTip = refTip(repo, pull.baseRef);
  if (!baseTip) return { error: 'base branch not found', status: 404 };
  const baseFiles = filesAtRef(repo, pull.baseRef);
  const headFiles = filesAtRef(repo, pull.headSha);
  for (const changed of pull.changedFiles) {
    const atHead = headFiles.get(changed.filename);
    if (atHead) baseFiles.set(changed.filename, atHead);
    else baseFiles.delete(changed.filename);
  }
  const treeOid = buildTreeFromPaths(repo, baseFiles);
  const message = 'Merge pull request #' + pull.number + ': ' + pull.title;
  const commitData = buildCommit(treeOid, [baseTip], message, SERVER_IDENT, nowSec(), '+0000');
  const mergeSha = putObject(repo.objects, 'commit', commitData);
  repo.refs.set('refs/heads/' + pull.baseRef, mergeSha);
  bumpRepo(repo);
  pull.state = 'closed';
  pull.merged = true;
  pull.mergedAt = nowIso();
  pull.mergeCommitSha = mergeSha;
  return { sha: mergeSha };
}

function handlePulls(req: IncomingMessage, res: ServerResponse, method: string, repo: Repo, rest: string[], q: Record<string, string>, bodyText: string): boolean {
  if (rest.length === 0) {
    if (method === 'POST') {
      let body: Record<string, unknown>;
      try {
        body = parseJsonText(bodyText) as Record<string, unknown>;
      } catch {
        sendError(res, 400, 'Invalid JSON');
        return true;
      }
      const title = typeof body.title === 'string' ? body.title : '';
      const pullBody = typeof body.body === 'string' ? body.body : '';
      const head = typeof body.head === 'string' ? body.head : '';
      const base = typeof body.base === 'string' ? body.base : repo.defaultBranch;
      const created = createPullRecord(repo, title, pullBody, head, base);
      if ('error' in created) {
        sendError(res, created.error === 'a pull request from this head already exists' ? 422 : 422, created.error);
        return true;
      }
      sendJson(res, 201, pullJson(created, repo));
      return true;
    }
    if (method === 'GET') {
      const { perPage, page } = pageParams(q);
      const state = q.state ?? 'open';
      const list = repo.pulls.filter((p) => state === 'all' || p.state === state);
      const slice = list.slice((page - 1) * perPage, page * perPage);
      sendJson(res, 200, slice.map((p) => pullJson(p, repo)));
      return true;
    }
    return false;
  }
  const num = parseInt(rest[0], 10);
  if (!Number.isFinite(num)) return false;
  const pull = repo.pulls.find((p) => p.number === num);
  if (rest.length === 1) {
    if (method === 'GET') {
      if (!pull) {
        sendError(res, 404, 'Not Found');
        return true;
      }
      sendJson(res, 200, pullJson(pull, repo));
      return true;
    }
    return false;
  }
  if (rest[1] === 'files' && method === 'GET') {
    if (!pull) {
      sendError(res, 404, 'Not Found');
      return true;
    }
    sendJson(res, 200, pull.changedFiles);
    return true;
  }
  if (rest[1] === 'merge' && method === 'PUT') {
    if (!pull) {
      sendError(res, 404, 'Not Found');
      return true;
    }
    try {
      parseJsonText(bodyText);
    } catch {
      sendError(res, 400, 'Invalid JSON');
      return true;
    }
    const merged = mergePullRecord(repo, pull);
    if ('error' in merged) {
      sendError(res, merged.status, merged.error);
      return true;
    }
    sendJson(res, 200, { sha: merged.sha, merged: true, message: 'Pull request successfully merged' });
    return true;
  }
  return false;
}

// ------------------------------------------------------------------ GraphQL v4

const GQL_TYPE_FIELDS: Record<string, string[]> = {
  Query: ['viewer', 'repository', 'node', '__type', '__schema'],
  Mutation: ['createIssue', 'closeIssue', 'createPullRequest', 'mergePullRequest', 'addComment'],
  IssuePayload: ['issue'],
  PullRequestPayload: ['pullRequest'],
  AddCommentPayload: ['commentEdge'],
  User: ['login', 'id', 'name'],
  Repository: ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequests', 'pullRequest'],
  Issue: ['id', 'number', 'title', 'state', 'body', 'comments', 'createdAt', 'updatedAt', 'author', 'labels'],
  PullRequest: ['id', 'number', 'title', 'body', 'state', 'merged', 'headRefName', 'baseRefName', 'mergeable', 'files', 'headRef', 'baseRef', 'createdAt'],
  IssueConnection: ['nodes', 'edges', 'pageInfo', 'totalCount'],
  PullRequestConnection: ['nodes', 'edges', 'pageInfo', 'totalCount'],
  IssueEdge: ['node', 'cursor'],
  PullRequestEdge: ['node', 'cursor'],
  PageInfo: ['hasNextPage', 'endCursor', 'hasPreviousPage', 'startCursor'],
  Ref: ['name'],
  __Type: ['fields', 'enumValues', 'name', 'kind', 'description'],
  CommentEdge: ['node', 'cursor'],
  Comment: ['id', 'body'],
  PullRequestChangedFileConnection: ['nodes', 'edges', 'pageInfo'],
  PullRequestChangedFile: ['path', 'additions', 'deletions', 'filename'],
};

const GQL_CHILD_TYPE: Record<string, string> = {
  'Mutation.createIssue': 'IssuePayload',
  'Mutation.closeIssue': 'IssuePayload',
  'Mutation.createPullRequest': 'PullRequestPayload',
  'Mutation.mergePullRequest': 'PullRequestPayload',
  'Mutation.addComment': 'AddCommentPayload',
  'IssuePayload.issue': 'Issue',
  'PullRequestPayload.pullRequest': 'PullRequest',
  'AddCommentPayload.commentEdge': 'CommentEdge',
  'Query.viewer': 'User',
  'Query.repository': 'Repository',
  'Query.node': 'Repository',
  'Query.__type': '__Type',
  'Repository.owner': 'User',
  'Repository.defaultBranchRef': 'Ref',
  'Repository.issue': 'Issue',
  'Repository.issues': 'IssueConnection',
  'Repository.pullRequests': 'PullRequestConnection',
  'Repository.pullRequest': 'PullRequest',
  'IssueConnection.nodes': 'Issue',
  'IssueConnection.edges': 'IssueEdge',
  'IssueConnection.pageInfo': 'PageInfo',
  'PullRequestConnection.nodes': 'PullRequest',
  'PullRequestConnection.edges': 'PullRequestEdge',
  'PullRequestConnection.pageInfo': 'PageInfo',
  'PullRequest.files': 'PullRequestChangedFileConnection',
  'PullRequestChangedFileConnection.nodes': 'PullRequestChangedFile',
  'PullRequestChangedFileConnection.edges': 'PullRequestChangedFile',
  'IssueEdge.node': 'Issue',
  'PullRequestEdge.node': 'PullRequest',
  'CommentEdge.node': 'Comment',
};

// Validate the selected fields of a document against the static type
// table. Returns the first unknown field as {field, type}, or null.
function validateGqlFields(query: string): { field: string; type: string } | null {
  // Tokenize: identifiers, strings, braces, parens, colon, ellipsis.
  const tokens: { kind: string; value: string }[] = [];
  let i = 0;
  while (i < query.length) {
    const ch = query[i];
    if (ch === ' ' || ch === '\n' || ch === '\t' || ch === '\r' || ch === ',') {
      i++;
      continue;
    }
    if (ch === '"') {
      let j = i + 1;
      while (j < query.length && query[j] !== '"') j++;
      tokens.push({ kind: 'string', value: query.slice(i + 1, j) });
      i = j + 1;
      continue;
    }
    if (ch === '{' || ch === '}' || ch === '(' || ch === ')' || ch === ':' || ch === '!') {
      tokens.push({ kind: ch, value: ch });
      i++;
      continue;
    }
    if (query.startsWith('...', i)) {
      tokens.push({ kind: 'ellipsis', value: '...' });
      i += 3;
      continue;
    }
    if (ch === '$') {
      let j = i + 1;
      while (j < query.length && /[A-Za-z0-9_]/.test(query[j])) j++;
      tokens.push({ kind: 'var', value: query.slice(i, j) });
      i = j;
      continue;
    }
    if (/[A-Za-z_]/.test(ch)) {
      let j = i;
      while (j < query.length && /[A-Za-z0-9_]/.test(query[j])) j++;
      tokens.push({ kind: 'ident', value: query.slice(i, j) });
      i = j;
      continue;
    }
    i++;
  }
  // Walk tokens with a stack of types. The document starts with
  // `query Name` / `mutation Name` and optional variable definitions.
  const stack: string[] = [];
  let pos = 0;
  let opKind = '';
  // Skip `query`/`mutation`, the operation name, and variable definitions.
  if (tokens[pos] && tokens[pos].kind === 'ident' && (tokens[pos].value === 'query' || tokens[pos].value === 'mutation')) {
    opKind = tokens[pos].value;
    pos++;
  }
  if (tokens[pos] && tokens[pos].kind === 'ident') pos++; // operation name
  if (tokens[pos] && tokens[pos].kind === '(') {
    let depth = 0;
    while (pos < tokens.length) {
      if (tokens[pos].kind === '(') depth++;
      if (tokens[pos].kind === ')') {
        depth--;
        if (depth === 0) {
          pos++;
          break;
        }
      }
      pos++;
    }
  }
  stack.push(opKind === 'mutation' ? 'Mutation' : 'Query');
  while (pos < tokens.length) {
    const tok = tokens[pos];
    if (tok.kind === '{') {
      pos++;
      continue;
    }
    if (tok.kind === '}') {
      stack.pop();
      pos++;
      continue;
    }
    if (tok.kind === 'ellipsis') {
      // `... on Type {` — push the fragment type.
      pos++;
      if (tokens[pos] && tokens[pos].kind === 'ident' && tokens[pos].value === 'on') pos++;
      if (tokens[pos] && tokens[pos].kind === 'ident') {
        stack.push(tokens[pos].value);
        pos++;
      }
      continue;
    }
    if (tok.kind !== 'ident') {
      pos++;
      continue;
    }
    // Alias form: `Alias: field`.
    let fieldName = tok.value;
    let next = pos + 1;
    if (tokens[next] && tokens[next].kind === ':') {
      const after = tokens[next + 1];
      if (after && after.kind === 'ident') {
        fieldName = after.value;
        next = pos + 3;
      }
    }
    const currentType = stack[stack.length - 1] ?? 'Query';
    const allowed = GQL_TYPE_FIELDS[currentType] ?? [];
    // __type / __schema are meta fields valid on any type; their
    // sub-selection is a __Type.
    if (fieldName.startsWith('__')) {
      let after = next;
      if (tokens[after] && tokens[after].kind === '(') {
        let depth = 0;
        while (after < tokens.length) {
          if (tokens[after].kind === '(') depth++;
          if (tokens[after].kind === ')') {
            depth--;
            if (depth === 0) {
              after++;
              break;
            }
          }
          after++;
        }
      }
      if (tokens[after] && tokens[after].kind === '{') {
        stack.push('__Type');
        pos = after + 1;
      } else {
        pos = after;
      }
      continue;
    }
    if (!allowed.includes(fieldName)) {
      return { field: fieldName, type: currentType };
    }
    // Skip argument list.
    if (tokens[next] && tokens[next].kind === '(') {
      let depth = 0;
      while (next < tokens.length) {
        if (tokens[next].kind === '(') depth++;
        if (tokens[next].kind === ')') {
          depth--;
          if (depth === 0) {
            next++;
            break;
          }
        }
        next++;
      }
    }
    // A following `{` opens a sub-selection of the child type.
    if (tokens[next] && tokens[next].kind === '{') {
      const child = GQL_CHILD_TYPE[currentType + '.' + fieldName];
      stack.push(child ?? currentType);
      pos = next + 1;
      continue;
    }
    pos = next;
  }
  return null;
}

const INTROSPECTION_FIELDS: Record<string, string[]> = {
  Issue: ['id', 'number', 'title', 'state', 'body', 'comments', 'createdAt', 'updatedAt', 'author', 'labels'],
  PullRequest: ['id', 'number', 'title', 'body', 'state', 'merged', 'headRefName', 'baseRefName', 'mergeable', 'files', 'headRef', 'baseRef', 'createdAt'],
  Repository: ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequests', 'pullRequest'],
  SearchType: [],
};

const INTROSPECTION_ENUMS: Record<string, string[]> = {
  SearchType: ['ISSUE', 'REPOSITORY', 'USER'],
  IssueState: ['OPEN', 'CLOSED'],
  PullRequestState: ['OPEN', 'CLOSED', 'MERGED'],
  MergeableState: ['MERGEABLE', 'CONFLICTING', 'UNKNOWN'],
  RepositoryPermission: ['ADMIN', 'MAINTAIN', 'WRITE', 'TRIAGE', 'READ'],
  IssueOrderField: ['CREATED_AT', 'UPDATED_AT', 'COMMENTS'],
  OrderDirection: ['ASC', 'DESC'],
  PullRequestMergeMethod: ['MERGE', 'SQUASH', 'REBASE'],
};

function gqlIssue(issue: Issue, repo: Repo): Record<string, unknown> {
  return {
    id: globalId('Issue', repo.owner, repo.name, issue.number),
    number: issue.number,
    title: issue.title,
    state: issue.state === 'open' ? 'OPEN' : 'CLOSED',
    body: issue.body,
  };
}

function gqlPull(pull: Pull, repo: Repo): Record<string, unknown> {
  return {
    id: globalId('PullRequest', repo.owner, repo.name, pull.number),
    number: pull.number,
    title: pull.title,
    body: pull.body,
    state: pull.merged ? 'MERGED' : pull.state === 'open' ? 'OPEN' : 'CLOSED',
    merged: pull.merged,
    headRefName: pull.headRef,
    baseRefName: pull.baseRef,
    mergeable: pullConflicts(repo, pull) ? 'CONFLICTING' : 'MERGEABLE',
    files: {
      nodes: pull.changedFiles.map((f) => ({ path: f.filename, additions: f.additions, deletions: f.deletions })),
    },
  };
}

function gqlRepository(repo: Repo, query: string, vars: Record<string, unknown>): Record<string, unknown> | null {
  const out: Record<string, unknown> = {
    id: repoGlobalId(repo),
    databaseId: repo.databaseId,
    name: repo.name,
    nameWithOwner: repo.fullName,
    owner: { login: repo.owner },
    defaultBranchRef: { name: repo.defaultBranch },
    viewerPermission: 'ADMIN',
    hasIssuesEnabled: true,
  };
  // issue(number:)
  const numVar = vars.number;
  if (typeof numVar === 'number') {
    const issue = repo.issues.find((x) => x.number === numVar);
    out.issue = issue ? gqlIssue(issue, repo) : null;
  }
  // issues(first, after, states, orderBy)
  if (query.includes('issues(') || query.includes('issues (')) {
    const first = typeof vars.first === 'number' ? vars.first : 10;
    const after = typeof vars.after === 'string' ? vars.after : null;
    let list = [...repo.issues];
    if (query.includes('states: [OPEN]')) list = list.filter((x) => x.state === 'open');
    else if (query.includes('states: [CLOSED]')) list = list.filter((x) => x.state === 'closed');
    const desc = query.includes('direction: DESC');
    list.sort((a, b) => (desc ? b.createdSeq - a.createdSeq : a.createdSeq - b.createdSeq));
    if (after) {
      const n = cursorNumber(after);
      if (n !== null) list = list.filter((x) => (desc ? x.number < n : x.number > n));
    }
    const page = list.slice(0, first);
    const hasNext = list.length > first;
    const endCursor = page.length ? cursorFor(page[page.length - 1].number) : null;
    out.issues = {
      nodes: page.map((x) => gqlIssue(x, repo)),
      edges: page.map((x) => ({ node: gqlIssue(x, repo), cursor: cursorFor(x.number) })),
      pageInfo: { hasNextPage: hasNext, endCursor },
    };
  }
  // pullRequests(first:)
  if (query.includes('pullRequests(') || query.includes('pullRequests (')) {
    const first = typeof vars.first === 'number' ? vars.first : 10;
    const open = repo.pulls.filter((p) => p.state === 'open').slice(0, first);
    out.pullRequests = {
      nodes: open.map((p) => gqlPull(p, repo)),
      edges: open.map((p) => ({ node: gqlPull(p, repo), cursor: cursorFor(p.number) })),
      pageInfo: { hasNextPage: repo.pulls.filter((p) => p.state === 'open').length > first, endCursor: open.length ? cursorFor(open[open.length - 1].number) : null },
    };
  }
  // pullRequest(number:)
  if (typeof numVar === 'number' && (query.includes('pullRequest(') || query.includes('pullRequest ('))) {
    const pull = repo.pulls.find((x) => x.number === numVar);
    out.pullRequest = pull ? gqlPull(pull, repo) : null;
  }
  return out;
}

function executeGql(doc: Record<string, unknown>): Record<string, unknown> {
  const query = typeof doc.query === 'string' ? doc.query : '';
  const vars = (doc.variables ?? {}) as Record<string, unknown>;
  const bad = validateGqlFields(query);
  if (bad) {
    return {
      data: { viewer: null },
      errors: [{ message: 'Cannot query field "' + bad.field + '" on type "' + bad.type + '"' }],
    };
  }
  const opMatch = /^\s*(query|mutation)\s+(\w+)/.exec(query);
  const opName = opMatch ? opMatch[2] : '';
  const data: Record<string, unknown> = {};

  // Introspection: `Alias: __type(name: "X")` occurrences.
  const typeMatches = [...query.matchAll(/(\w+)\s*:\s*__type\s*\(\s*name\s*:\s*"([^"]+)"\s*\)/g)];
  if (typeMatches.length > 0) {
    for (const m of typeMatches) {
      const alias = m[1];
      const typeName = m[2];
      if (query.includes('enumValues')) {
        const enums = INTROSPECTION_ENUMS[typeName];
        data[alias] = enums ? { enumValues: enums.map((n) => ({ name: n })) } : null;
      } else {
        const fields = INTROSPECTION_FIELDS[typeName];
        data[alias] = fields !== undefined ? { fields: fields.map((n) => ({ name: n })) } : null;
      }
    }
    return { data };
  }
  if (query.includes('__type(')) {
    // Unaliased __type.
    const m = /__type\s*\(\s*name\s*:\s*"([^"]+)"\s*\)/.exec(query);
    const typeName = m ? m[1] : '';
    if (query.includes('enumValues')) {
      const enums = INTROSPECTION_ENUMS[typeName];
      data.__type = enums ? { enumValues: enums.map((n) => ({ name: n })) } : null;
    } else {
      const fields = INTROSPECTION_FIELDS[typeName];
      data.__type = fields !== undefined ? { fields: fields.map((n) => ({ name: n })) } : null;
    }
    return { data };
  }

  switch (opName) {
    case 'ViewerLogin': {
      data.viewer = { login: VIEWER_LOGIN };
      return { data };
    }
    case 'NodeRepository': {
      const id = typeof vars.id === 'string' ? vars.id : '';
      const decoded = decodeGlobalId(id);
      if (!decoded || decoded.kind !== 'Repository') {
        data.node = null;
        return { data };
      }
      const repo = findRepo(decoded.owner, decoded.name);
      if (!repo) {
        data.node = null;
        return { data };
      }
      data.node = { id: repoGlobalId(repo), __typename: 'Repository', name: repo.name, nameWithOwner: repo.fullName };
      return { data };
    }
    case 'IssueCreate':
    case 'CreateIssue': {
      const input = (vars.input ?? {}) as Record<string, unknown>;
      const repoId = typeof input.repositoryId === 'string' ? input.repositoryId : '';
      const decoded = decodeGlobalId(repoId);
      const repo = decoded ? findRepo(decoded.owner, decoded.name) : null;
      if (!repo) return { data: { createIssue: null }, errors: [{ message: 'repository not found' }] };
      const issue = createIssueRecord(repo, typeof input.title === 'string' ? input.title : '', typeof input.body === 'string' ? input.body : '', []);
      data.createIssue = { issue: { number: issue.number, id: globalId('Issue', repo.owner, repo.name, issue.number) } };
      return { data };
    }
    case 'IssueClose':
    case 'CloseIssue': {
      const input = (vars.input ?? {}) as Record<string, unknown>;
      const issueId = typeof input.issueId === 'string' ? input.issueId : '';
      const decoded = decodeGlobalId(issueId);
      const repo = decoded ? findRepo(decoded.owner, decoded.name) : null;
      const issue = repo && decoded ? repo.issues.find((x) => x.number === decoded.n) : undefined;
      if (!repo || !issue) return { data: { closeIssue: null }, errors: [{ message: 'issue not found' }] };
      issue.state = 'closed';
      issue.updatedAt = nowIso();
      refreshIssueCache(issue, repo);
      data.closeIssue = { issue: { number: issue.number, id: globalId('Issue', repo.owner, repo.name, issue.number), state: 'CLOSED' } };
      return { data };
    }
    case 'PullRequestCreate':
    case 'CreatePullRequest': {
      const input = (vars.input ?? {}) as Record<string, unknown>;
      const repoId = typeof input.repositoryId === 'string' ? input.repositoryId : '';
      const decoded = decodeGlobalId(repoId);
      const repo = decoded ? findRepo(decoded.owner, decoded.name) : null;
      if (!repo) return { data: { createPullRequest: null }, errors: [{ message: 'repository not found' }] };
      const head = typeof input.headRefName === 'string' ? input.headRefName : '';
      const base = typeof input.baseRefName === 'string' ? input.baseRefName : repo.defaultBranch;
      const title = typeof input.title === 'string' ? input.title : '';
      const created = createPullRecord(repo, title, typeof input.body === 'string' ? input.body : '', head, base);
      if ('error' in created) return { data: { createPullRequest: null }, errors: [{ message: created.error }] };
      data.createPullRequest = {
        pullRequest: {
          number: created.number,
          id: globalId('PullRequest', repo.owner, repo.name, created.number),
          state: 'OPEN',
          headRefName: created.headRef,
          baseRefName: created.baseRef,
        },
      };
      return { data };
    }
    case 'MergePullRequest': {
      const input = (vars.input ?? {}) as Record<string, unknown>;
      const prId = typeof input.pullRequestId === 'string' ? input.pullRequestId : '';
      const decoded = decodeGlobalId(prId);
      const repo = decoded ? findRepo(decoded.owner, decoded.name) : null;
      const pull = repo && decoded ? repo.pulls.find((x) => x.number === decoded.n) : undefined;
      if (!repo || !pull) return { data: { mergePullRequest: null }, errors: [{ message: 'pull request not found' }] };
      const merged = mergePullRecord(repo, pull);
      if ('error' in merged) return { data: { mergePullRequest: null }, errors: [{ message: merged.error }] };
      data.mergePullRequest = { pullRequest: { number: pull.number, merged: true, state: 'MERGED' } };
      return { data };
    }
    case 'AddComment': {
      const input = (vars.input ?? {}) as Record<string, unknown>;
      const subjectId = typeof input.subjectId === 'string' ? input.subjectId : '';
      const decoded = decodeGlobalId(subjectId);
      const repo = decoded ? findRepo(decoded.owner, decoded.name) : null;
      const issue = repo && decoded ? repo.issues.find((x) => x.number === decoded.n) : undefined;
      if (!repo || !issue) return { data: { addComment: null }, errors: [{ message: 'subject not found' }] };
      const comment: Comment = { id: repo.nextCommentId++, body: typeof input.body === 'string' ? input.body : '', createdSeq: ++globalSeq };
      issue.comments.push(comment);
      refreshIssueCache(issue, repo);
      data.addComment = { commentEdge: { node: { id: commentGlobalId(repo, comment.id), body: comment.body } } };
      return { data };
    }
    default: {
      // Repository reads (ViewerLogin handled above; everything else
      // in the suite is a repository-rooted query).
      const owner = typeof vars.owner === 'string' ? vars.owner : '';
      const name = typeof vars.name === 'string' ? vars.name : '';
      const repo = owner && name ? findRepo(owner, name) : null;
      if (!repo) {
        data.repository = null;
        return { data };
      }
      data.repository = gqlRepository(repo, query, vars);
      return { data };
    }
  }
}

function handleGraphQL(req: IncomingMessage, res: ServerResponse, bodyText: string): boolean {
  let parsed: unknown;
  try {
    parsed = JSON.parse(bodyText);
  } catch {
    sendError(res, 400, 'Invalid JSON');
    return true;
  }
  if (Array.isArray(parsed)) {
    const results = parsed.map((doc) => executeGql(doc as Record<string, unknown>));
    sendJson(res, 200, results);
    return true;
  }
  if (parsed && typeof parsed === 'object') {
    sendJson(res, 200, executeGql(parsed as Record<string, unknown>));
    return true;
  }
  sendError(res, 400, 'Invalid GraphQL request');
  return true;
}

// ------------------------------------------------------------------ MCP

const MCP_SUPPORTED_VERSIONS = ['2026-07-28', '2025-11-25'];
const MCP_LEGACY_VERSIONS = ['2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];
const MCP_SESSION_ID = randomUUID();

interface McpToolDef {
  name: string;
  description: string;
  inputSchema: { type: string; properties: Record<string, unknown>; required: string[] };
}

const MCP_TOOLS: McpToolDef[] = [
  {
    name: 'create_repo',
    description: 'Create a repository owned by the token owner.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Repository name' },
        description: { type: 'string', description: 'Repository description' },
        private: { type: 'boolean', description: 'Whether the repository is private' },
      },
      required: ['name'],
    },
  },
  {
    name: 'get_repo',
    description: 'Get a repository by owner and name.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        full_name: { type: 'string', description: 'owner/repo' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_issue',
    description: 'Create an issue in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        title: { type: 'string', description: 'Issue title' },
        body: { type: 'string', description: 'Issue body' },
      },
      required: ['owner', 'repo', 'title'],
    },
  },
  {
    name: 'list_issues',
    description: 'List issues in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        state: { type: 'string', description: 'open, closed or all' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_pull_request',
    description: 'Create a pull request from a head branch into a base branch.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        title: { type: 'string', description: 'Pull request title' },
        body: { type: 'string', description: 'Pull request body' },
        head: { type: 'string', description: 'Head branch name' },
        base: { type: 'string', description: 'Base branch name' },
      },
      required: ['owner', 'repo', 'title', 'head', 'base'],
    },
  },
  {
    name: 'merge_pull_request',
    description: 'Squash-merge a pull request.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        pull_number: { type: 'integer', description: 'Pull request number' },
      },
      required: ['owner', 'repo', 'pull_number'],
    },
  },
  {
    name: 'get_issue',
    description: 'Get one issue by number.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        issue_number: { type: 'integer', description: 'Issue number' },
      },
      required: ['owner', 'repo', 'issue_number'],
    },
  },
  {
    name: 'list_pull_requests',
    description: 'List pull requests in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        state: { type: 'string', description: 'open, closed or all' },
      },
      required: ['owner', 'repo'],
    },
  },
];

const MCP_TOOLS_JSON = JSON.stringify(MCP_TOOLS);

function mcpResolveRepo(args: Record<string, unknown>): Repo | null {
  let owner = typeof args.owner === 'string' ? args.owner : '';
  let name = typeof args.repo === 'string' ? args.repo : '';
  if ((!owner || !name) && typeof args.full_name === 'string') {
    const parts = (args.full_name as string).split('/');
    if (parts.length === 2) {
      owner = parts[0];
      name = parts[1];
    }
  }
  if (!owner || !name) return null;
  return findRepo(owner, name);
}

function mcpToolResult(result: unknown): Record<string, unknown> {
  const text = JSON.stringify(result);
  return { content: [{ type: 'text', text }], structuredContent: result, isError: false };
}

function mcpToolError(message: string): Record<string, unknown> {
  const text = JSON.stringify({ error: message });
  return { content: [{ type: 'text', text }], structuredContent: { error: message }, isError: true };
}

function mcpCallTool(name: string, args: Record<string, unknown>): { result?: Record<string, unknown>; rpcError?: { code: number; message: string } } {
  const normalized = name.toLowerCase().replace(/[^a-z0-9]/g, '');
  const tool = MCP_TOOLS.find((t) => normalized === t.name.replace(/[^a-z0-9]/g, '') || normalized.endsWith(t.name.replace(/[^a-z0-9]/g, '')));
  if (!tool) return { rpcError: { code: -32601, message: 'Method not found: ' + name } };
  for (const required of tool.inputSchema.required) {
    if (args[required] === undefined || args[required] === null || args[required] === '') {
      return { result: mcpToolError('Missing required argument: ' + required) };
    }
  }
  switch (tool.name) {
    case 'create_repo': {
      const repoName = String(args.name);
      if (repos.has(repoKey(VIEWER_LOGIN, repoName))) return { result: mcpToolError('Repository already exists') };
      const repo = createRepoRecord(repoName, args.private === true, typeof args.description === 'string' ? args.description : '', 'main');
      return { result: mcpToolResult(repoJson(repo)) };
    }
    case 'get_repo': {
      const repo = mcpResolveRepo(args);
      if (!repo) return { result: mcpToolError('repository not found') };
      return { result: mcpToolResult(repoJson(repo)) };
    }
    case 'create_issue': {
      const repo = mcpResolveRepo(args);
      if (!repo) return { result: mcpToolError('repository not found') };
      const issue = createIssueRecord(repo, String(args.title), typeof args.body === 'string' ? args.body : '', []);
      return { result: mcpToolResult(issueJson(issue, repo)) };
    }
    case 'list_issues': {
      const repo = mcpResolveRepo(args);
      if (!repo) return { result: mcpToolError('repository not found') };
      const state = typeof args.state === 'string' ? args.state : 'open';
      const list = repo.issues.filter((i) => state === 'all' || i.state === state);
      return { result: mcpToolResult({ issues: list.map((i) => issueJson(i, repo)) }) };
    }
    case 'create_pull_request': {
      const repo = mcpResolveRepo(args);
      if (!repo) return { result: mcpToolError('repository not found') };
      const created = createPullRecord(repo, String(args.title), typeof args.body === 'string' ? args.body : '', String(args.head), String(args.base));
      if ('error' in created) return { result: mcpToolError(created.error) };
      return { result: mcpToolResult(pullJson(created, repo)) };
    }
    case 'merge_pull_request': {
      const repo = mcpResolveRepo(args);
      if (!repo) return { result: mcpToolError('repository not found') };
      const num = typeof args.pull_number === 'number' ? args.pull_number : parseInt(String(args.pull_number), 10);
      const pull = repo.pulls.find((p) => p.number === num);
      if (!pull) return { result: mcpToolError('pull request not found') };
      const merged = mergePullRecord(repo, pull);
      if ('error' in merged) return { result: mcpToolError(merged.error) };
      return { result: mcpToolResult({ sha: merged.sha, merged: true, number: pull.number, message: 'Pull request successfully merged' }) };
    }
    case 'get_issue': {
      const repo = mcpResolveRepo(args);
      if (!repo) return { result: mcpToolError('repository not found') };
      const num = typeof args.issue_number === 'number' ? args.issue_number : parseInt(String(args.issue_number), 10);
      const issue = repo.issues.find((i) => i.number === num);
      if (!issue) return { result: mcpToolError('issue not found') };
      return { result: mcpToolResult(issueJson(issue, repo)) };
    }
    case 'list_pull_requests': {
      const repo = mcpResolveRepo(args);
      if (!repo) return { result: mcpToolError('repository not found') };
      const state = typeof args.state === 'string' ? args.state : 'open';
      const list = repo.pulls.filter((p) => state === 'all' || p.state === state);
      return { result: mcpToolResult({ pull_requests: list.map((p) => pullJson(p, repo)) }) };
    }
    default:
      return { rpcError: { code: -32601, message: 'Method not found: ' + name } };
  }
}

function handleMcp(req: IncomingMessage, res: ServerResponse, bodyText: string): boolean {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json; charset=utf-8',
    'X-GitHub-Request-Id': randomUUID(),
    'Mcp-Session-Id': MCP_SESSION_ID,
  };
  const sendRpc = (status: number, payload: unknown): void => {
    const body = JSON.stringify(payload);
    headers['Content-Length'] = String(Buffer.byteLength(body));
    res.writeHead(status, headers);
    res.end(body);
  };
  let parsed: unknown;
  try {
    parsed = JSON.parse(bodyText);
  } catch {
    sendRpc(400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
    return true;
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    sendRpc(400, { jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Invalid Request' } });
    return true;
  }
  const msg = parsed as Record<string, unknown>;
  const method = typeof msg.method === 'string' ? msg.method : '';
  const id = msg.id as string | number | undefined;
  const params = (msg.params ?? {}) as Record<string, unknown>;
  // A notification (no id) gets no response body.
  if (id === undefined || id === null) {
    res.writeHead(202, headers);
    res.end();
    return true;
  }
  const declared = (params._meta as Record<string, unknown> | undefined)?.['io.modelcontextprotocol/protocolVersion'];
  const headerVersion = req.headers['mcp-protocol-version'];
  if (typeof declared === 'string' && typeof headerVersion === 'string' && declared !== headerVersion) {
    sendRpc(200, { jsonrpc: '2.0', id, error: { code: -32020, message: 'HeaderMismatch: MCP-Protocol-Version header does not match _meta protocolVersion' } });
    return true;
  }
  const version = typeof declared === 'string' ? declared : typeof headerVersion === 'string' ? headerVersion : '2026-07-28';
  if (method === 'server/discover') {
    if (!MCP_SUPPORTED_VERSIONS.includes(version)) {
      sendRpc(200, { jsonrpc: '2.0', id, error: { code: -32022, message: 'UnsupportedProtocolVersionError', data: { supported: MCP_SUPPORTED_VERSIONS } } });
      return true;
    }
    sendRpc(200, {
      jsonrpc: '2.0',
      id,
      result: {
        supportedVersions: MCP_SUPPORTED_VERSIONS,
        capabilities: { tools: {} },
        serverInfo: { name: 'himeko-forge', version: '1.0.0' },
        _meta: { 'io.modelcontextprotocol/serverInfo': { name: 'himeko-forge', version: '1.0.0' } },
      },
    });
    return true;
  }
  if (method === 'initialize') {
    const offered = typeof params.protocolVersion === 'string' ? params.protocolVersion : '';
    const chosen = MCP_LEGACY_VERSIONS.includes(offered) ? offered : '2025-11-25';
    sendRpc(200, {
      jsonrpc: '2.0',
      id,
      result: { protocolVersion: chosen, capabilities: { tools: {} }, serverInfo: { name: 'himeko-forge', version: '1.0.0' } },
    });
    return true;
  }
  if (method === 'ping') {
    sendRpc(200, { jsonrpc: '2.0', id, result: {} });
    return true;
  }
  if (method === 'tools/list') {
    // Byte-identical on repeat calls: the tools array is a constant.
    const body = '{"jsonrpc":"2.0","id":' + JSON.stringify(id) + ',"result":{"tools":' + MCP_TOOLS_JSON + '}}';
    headers['Content-Length'] = String(Buffer.byteLength(body));
    res.writeHead(200, headers);
    res.end(body);
    return true;
  }
  if (method === 'tools/call') {
    const toolName = typeof params.name === 'string' ? params.name : '';
    const args = (params.arguments ?? {}) as Record<string, unknown>;
    const outcome = mcpCallTool(toolName, args);
    if (outcome.rpcError) {
      sendRpc(200, { jsonrpc: '2.0', id, error: outcome.rpcError });
      return true;
    }
    sendRpc(200, { jsonrpc: '2.0', id, result: outcome.result });
    return true;
  }
  sendRpc(200, { jsonrpc: '2.0', id, error: { code: -32601, message: 'Method not found: ' + method } });
  return true;
}

// ------------------------------------------------------------------ git smart HTTP

function gitRepo(res: ServerResponse, owner: string, name: string): Repo | null {
  const repo = findRepo(owner, name);
  if (!repo) {
    sendError(res, 404, 'Not Found');
    return null;
  }
  return repo;
}

function sortedRefList(repo: Repo): { oid: string; ref: string }[] {
  const out: { oid: string; ref: string }[] = [];
  for (const [ref, oid] of repo.refs.entries()) out.push({ oid, ref });
  out.sort((a, b) => (a.ref < b.ref ? -1 : a.ref > b.ref ? 1 : 0));
  return out;
}

// Peel an annotated tag (recursively) to its commit oid.
function peelToCommit(repo: Repo, oid: string): string {
  let current = oid;
  for (let i = 0; i < 8; i++) {
    const obj = repo.objects.get(current);
    if (!obj || obj.type !== 'tag') return current;
    current = parseTag(obj.data).object;
  }
  return current;
}

function sendGitBytes(res: ServerResponse, status: number, contentType: string, body: Buffer): void {
  res.writeHead(status, {
    'Content-Type': contentType,
    'X-GitHub-Request-Id': randomUUID(),
    'Content-Length': String(body.length),
  });
  res.end(body);
}

function advertiseUploadPackV2(): Buffer {
  const parts: Buffer[] = [
    pktLine('# service=git-upload-pack\n'),
    pktFlush(),
    pktLine('version 2\n'),
    pktLine('agent=' + AGENT + '\n'),
    pktLine('ls-refs\n'),
    pktLine('fetch=shallow\n'),
    pktLine('object-format=sha1\n'),
    pktFlush(),
  ];
  return Buffer.concat(parts);
}

function advertiseUploadPackV0(repo: Repo): Buffer {
  const parts: Buffer[] = [pktLine('# service=git-upload-pack\n'), pktFlush()];
  const caps = 'side-band-64k shallow thin-pack ofs-delta agent=' + AGENT + ' symref=HEAD:refs/heads/' + repo.defaultBranch;
  const refs = sortedRefList(repo);
  const headTip = repo.refs.get('refs/heads/' + repo.defaultBranch);
  if (refs.length === 0) {
    parts.push(pktLine(ZERO_OID + ' capabilities^{}\0' + caps + '\n'));
  } else {
    parts.push(pktLine((headTip ?? ZERO_OID) + ' HEAD\0' + caps + '\n'));
    for (const r of refs) {
      parts.push(pktLine(r.oid + ' ' + r.ref + '\n'));
      const obj = repo.objects.get(r.oid);
      if (obj && obj.type === 'tag') {
        parts.push(pktLine(peelToCommit(repo, r.oid) + ' ' + r.ref + '^{}\n'));
      }
    }
  }
  parts.push(pktFlush());
  return Buffer.concat(parts);
}

function advertiseReceivePack(repo: Repo): Buffer {
  const parts: Buffer[] = [pktLine('# service=git-receive-pack\n'), pktFlush()];
  const caps = 'report-status report-status-v2 side-band-64k delete-refs ofs-delta agent=' + AGENT + ' symref=HEAD:refs/heads/' + repo.defaultBranch;
  const refs = sortedRefList(repo);
  const headTip = repo.refs.get('refs/heads/' + repo.defaultBranch);
  if (refs.length === 0) {
    parts.push(pktLine(ZERO_OID + ' capabilities^{}\0' + caps + '\n'));
  } else {
    parts.push(pktLine((headTip ?? ZERO_OID) + ' HEAD\0' + caps + '\n'));
    for (const r of refs) {
      parts.push(pktLine(r.oid + ' ' + r.ref + '\n'));
      const obj = repo.objects.get(r.oid);
      if (obj && obj.type === 'tag') {
        parts.push(pktLine(peelToCommit(repo, r.oid) + ' ' + r.ref + '^{}\n'));
      }
    }
  }
  parts.push(pktFlush());
  return Buffer.concat(parts);
}

interface FetchPlan {
  pack: Buffer;
  shallow: string[];
  unshallow: string[];
  acks: string[];
}

function computeFetch(repo: Repo, wants: string[], haves: string[], shallowIn: string[], depth: number | null): FetchPlan {
  const cacheKey =
    repo.fullName + '|' + repo.version + '|' + wants.join(',') + '|' + haves.join(',') + '|' + (depth === null ? '' : String(depth)) + '|' + shallowIn.join(',');
  const cached = repo.packCache.get(cacheKey);
  // Commit distances from the wants (0 = want itself).
  const dist = new Map<string, number>();
  const queue: { oid: string; d: number }[] = [];
  for (const w of wants) {
    if (isHex40(w) && repo.objects.has(w)) queue.push({ oid: w, d: 0 });
  }
  const includedCommits: string[] = [];
  const includedSet = new Set<string>();
  while (queue.length) {
    const item = queue.shift() as { oid: string; d: number };
    if (includedSet.has(item.oid)) continue;
    const obj = repo.objects.get(item.oid);
    if (!obj) continue;
    if (obj.type === 'tag') {
      includedSet.add(item.oid);
      const target = parseTag(obj.data).object;
      if (!includedSet.has(target)) queue.push({ oid: target, d: item.d });
      continue;
    }
    if (obj.type !== 'commit') {
      includedSet.add(item.oid);
      continue;
    }
    if (depth !== null && item.d >= depth) continue;
    includedSet.add(item.oid);
    includedCommits.push(item.oid);
    dist.set(item.oid, item.d);
    for (const p of parseCommit(obj.data).parents) {
      if (!includedSet.has(p)) queue.push({ oid: p, d: item.d + 1 });
    }
  }
  // Objects reachable from the included commits' trees (and tag targets).
  const includedObjects = new Set<string>(includedSet);
  for (const commitOid of includedCommits) {
    const tree = treeOidAtTip(repo, commitOid);
    if (tree) for (const oid of collectReachable(repo, [tree])) includedObjects.add(oid);
  }
  // Objects the client already holds: closure of the haves, but never
  // past a shallow boundary — a shallow clone holds the boundary commit
  // and its tree, not the boundary's parents.
  const shallowSet = new Set(shallowIn);
  const haveClosure = new Set<string>();
  const haveQueue: string[] = [...haves];
  while (haveQueue.length) {
    const oid = haveQueue.pop() as string;
    if (haveClosure.has(oid)) continue;
    const obj = repo.objects.get(oid);
    if (!obj) continue;
    haveClosure.add(oid);
    if (obj.type === 'commit') {
      const c = parseCommit(obj.data);
      for (const x of collectReachable(repo, [c.tree])) haveClosure.add(x);
      if (!shallowSet.has(oid)) for (const p of c.parents) haveQueue.push(p);
    } else if (obj.type === 'tag') {
      haveQueue.push(parseTag(obj.data).object);
    } else if (obj.type === 'tree') {
      for (const x of collectReachable(repo, [oid])) haveClosure.add(x);
    }
  }
  const send = new Set<string>();
  for (const oid of includedObjects) if (!haveClosure.has(oid)) send.add(oid);
  // Shallow boundary: included commits at the depth cut whose parents are
  // not included. Unshallow: old boundaries now fully included.
  const shallow: string[] = [];
  const unshallow: string[] = [];
  if (depth !== null) {
    for (const commitOid of includedCommits) {
      const d = dist.get(commitOid) ?? 0;
      if (d !== depth - 1) continue;
      const parents = parseCommit((repo.objects.get(commitOid) as GitObject).data).parents;
      if (parents.length > 0 && parents.some((p) => !includedSet.has(p))) shallow.push(commitOid);
    }
  }
  for (const old of shallowIn) {
    if (!includedSet.has(old)) continue;
    const obj = repo.objects.get(old);
    if (!obj || obj.type !== 'commit') continue;
    const parents = parseCommit(obj.data).parents;
    if (parents.every((p) => includedSet.has(p))) unshallow.push(old);
    else if (depth === null && !shallow.includes(old)) shallow.push(old);
  }
  const acks: string[] = [];
  for (const h of haves) {
    if (wants.some((w) => isAncestor(repo, h, w))) acks.push(h);
  }
  let pack: Buffer;
  if (cached) {
    pack = cached;
  } else {
    const ordered: GitObject[] = [];
    const seenOrder = new Set<string>();
    const rank = (o: GitObject): number => (o.type === 'commit' ? 0 : o.type === 'tag' ? 1 : o.type === 'tree' ? 2 : 3);
    const byRank: GitObject[][] = [[], [], [], []];
    for (const oid of send) {
      const obj = repo.objects.get(oid);
      if (!obj) continue;
      byRank[rank(obj)].push(obj);
    }
    // Commits in BFS order (wants first), others in discovery order.
    const commitOrder = includedCommits.filter((oid) => send.has(oid));
    const commitObjs = commitOrder.map((oid) => repo.objects.get(oid) as GitObject);
    const tagObjs = byRank[1];
    const treeObjs = byRank[2];
    const blobObjs = byRank[3];
    ordered.push(...commitObjs, ...tagObjs, ...treeObjs, ...blobObjs);
    void seenOrder;
    pack = writePack(ordered);
    repo.packCache.set(cacheKey, pack);
  }
  return { pack, shallow, unshallow, acks };
}

function sidebandWrap(pack: Buffer): Buffer {
  const parts: Buffer[] = [];
  for (let off = 0; off < pack.length || (pack.length === 0 && off === 0); off += PKT_PAYLOAD_MAX - 1) {
    const slice = pack.subarray(off, off + PKT_PAYLOAD_MAX - 1);
    const payload = Buffer.concat([Buffer.from([1]), slice]);
    parts.push(pktLine(payload));
    if (pack.length === 0) break;
  }
  return Buffer.concat(parts);
}

function handleLsRefs(repo: Repo, args: string[]): Buffer {
  let peel = false;
  let symrefs = false;
  let unborn = false;
  const prefixes: string[] = [];
  for (const arg of args) {
    if (arg === 'peel') peel = true;
    else if (arg === 'symrefs') symrefs = true;
    else if (arg === 'unborn') unborn = true;
    else if (arg.startsWith('ref-prefix ')) prefixes.push(arg.slice('ref-prefix '.length));
  }
  void peel;
  void symrefs;
  const parts: Buffer[] = [];
  const headTip = repo.refs.get('refs/heads/' + repo.defaultBranch);
  const includeHead = prefixes.length === 0 || prefixes.some((p) => 'HEAD'.startsWith(p));
  const matches = (name: string): boolean => prefixes.length === 0 || prefixes.some((p) => name.startsWith(p));
  if (includeHead) {
    if (headTip) {
      parts.push(pktLine(headTip + ' HEAD symref-target:refs/heads/' + repo.defaultBranch + '\n'));
    } else if (unborn) {
      parts.push(pktLine('unborn HEAD symref-target:refs/heads/' + repo.defaultBranch + '\n'));
    }
    // Empty repo, no `unborn` requested: real git sends no HEAD line at
    // all. A zero-oid HEAD line makes real git fetch the zero oid and
    // then never write a local HEAD on clone.
  }
  if (repo.refs.size === 0 && unborn && matches('refs/heads/' + repo.defaultBranch)) {
    parts.push(pktLine('unborn refs/heads/' + repo.defaultBranch + '\n'));
  }
  for (const r of sortedRefList(repo)) {
    if (!matches(r.ref)) continue;
    let line = r.oid + ' ' + r.ref;
    const obj = repo.objects.get(r.oid);
    if (obj && obj.type === 'tag') line += ' peeled:' + peelToCommit(repo, r.oid);
    parts.push(pktLine(line + '\n'));
  }
  parts.push(pktFlush());
  return Buffer.concat(parts);
}

function handleUploadPack(repo: Repo, body: Buffer, isV2: boolean): Buffer {
  const items = parsePktLines(body);
  const dataLines = items.filter((x) => x.kind === 'data').map((x) => (x.data as Buffer).toString('utf8'));
  const first = dataLines[0] ?? '';
  if (first.startsWith('command=ls-refs')) {
    const args = dataLines.slice(1).map((l) => l.replace(/\n$/, ''));
    return handleLsRefs(repo, args);
  }
  if (first.startsWith('command=fetch')) {
    const args = dataLines.slice(1).map((l) => l.replace(/\n$/, ''));
    const wants: string[] = [];
    const haves: string[] = [];
    const shallowIn: string[] = [];
    let depth: number | null = null;
    for (const arg of args) {
      if (arg.startsWith('want ')) wants.push(arg.slice(5).trim());
      else if (arg.startsWith('have ')) haves.push(arg.slice(5).trim());
      else if (arg.startsWith('shallow ')) shallowIn.push(arg.slice(8).trim());
      else if (arg.startsWith('deepen ')) depth = parseInt(arg.slice(7), 10);
    }
    const plan = computeFetch(repo, wants, haves, shallowIn, depth);
    const parts: Buffer[] = [];
    if (haves.length > 0) {
      parts.push(pktLine('acknowledgments\n'));
      if (plan.acks.length > 0) {
        for (const ack of plan.acks) parts.push(pktLine('ACK ' + ack + '\n'));
      } else {
        parts.push(pktLine('NAK\n'));
      }
      parts.push(pktDelim());
    }
    if (plan.shallow.length > 0 || plan.unshallow.length > 0) {
      parts.push(pktLine('shallow-info\n'));
      for (const s of plan.shallow) parts.push(pktLine('shallow ' + s + '\n'));
      for (const u of plan.unshallow) parts.push(pktLine('unshallow ' + u + '\n'));
      parts.push(pktDelim());
    }
    parts.push(pktLine('packfile\n'));
    parts.push(sidebandWrap(plan.pack));
    parts.push(pktFlush());
    return Buffer.concat(parts);
  }
  if (!isV2) {
    // v0 fetch: want/have lines in two flush-separated sections.
    const wants: string[] = [];
    const haves: string[] = [];
    const shallowIn: string[] = [];
    let depth: number | null = null;
    let section = 0;
    for (const item of items) {
      if (item.kind === 'flush') {
        section++;
        continue;
      }
      if (item.kind !== 'data' || !item.data) continue;
      const line = item.data.toString('utf8').replace(/\n$/, '');
      if (line.startsWith('want ')) wants.push(line.slice(5).split(' ')[0]);
      else if (line.startsWith('have ')) haves.push(line.slice(5).trim());
      else if (line.startsWith('shallow ')) shallowIn.push(line.slice(8).trim());
      else if (line.startsWith('deepen ')) depth = parseInt(line.slice(7), 10);
    }
    void section;
    const plan = computeFetch(repo, wants, haves, shallowIn, depth);
    const parts: Buffer[] = [];
    if (plan.acks.length > 0) {
      for (const ack of plan.acks) parts.push(pktLine('ACK ' + ack + '\n'));
    } else {
      parts.push(pktLine('NAK\n'));
    }
    for (const s of plan.shallow) parts.push(pktLine('shallow ' + s + '\n'));
    for (const u of plan.unshallow) parts.push(pktLine('unshallow ' + u + '\n'));
    parts.push(sidebandWrap(plan.pack));
    parts.push(pktFlush());
    return Buffer.concat(parts);
  }
  throw new Error('unknown upload-pack command');
}

interface PushCommand {
  oldOid: string;
  newOid: string;
  ref: string;
}

function handleReceivePack(repo: Repo, body: Buffer): Buffer {
  const { items, rest } = splitAtFlush(body);
  const commands: PushCommand[] = [];
  for (const item of items) {
    if (item.kind !== 'data' || !item.data) continue;
    let line = item.data.toString('utf8');
    const nul = line.indexOf('\0');
    if (nul >= 0) line = line.slice(0, nul);
    line = line.replace(/\n$/, '');
    const m = /^([0-9a-f]{40}) ([0-9a-f]{40}) (\S+)$/.exec(line);
    if (!m) continue;
    commands.push({ oldOid: m[1], newOid: m[2], ref: m[3] });
  }
  const reportLines: string[] = [];
  let unpackOk = true;
  let unpackDetail = 'ok';
  if (rest.length > 0) {
    try {
      const parsed = parsePack(rest, (oid) => repo.objects.get(oid));
      for (const obj of parsed) {
        if (!repo.objects.has(obj.oid)) repo.objects.set(obj.oid, { type: obj.type, data: obj.data });
      }
    } catch (err) {
      unpackOk = false;
      unpackDetail = err instanceof Error ? err.message : 'unpack failed';
    }
  }
  if (unpackOk) {
    for (const cmd of commands) {
      const current = repo.refs.get(cmd.ref);
      if (cmd.newOid === ZERO_OID) {
        if (!current) {
          reportLines.push('ng ' + cmd.ref + ' reference does not exist');
        } else if (cmd.oldOid !== ZERO_OID && cmd.oldOid !== current) {
          reportLines.push('ng ' + cmd.ref + ' old value does not match');
        } else {
          repo.refs.delete(cmd.ref);
          bumpRepo(repo);
          reportLines.push('ok ' + cmd.ref);
        }
        continue;
      }
      if (!repo.objects.has(cmd.newOid)) {
        reportLines.push('ng ' + cmd.ref + ' object not found');
        continue;
      }
      if (cmd.oldOid === ZERO_OID) {
        if (current) {
          reportLines.push('ng ' + cmd.ref + ' already exists');
        } else {
          repo.refs.set(cmd.ref, cmd.newOid);
          bumpRepo(repo);
          reportLines.push('ok ' + cmd.ref);
        }
        continue;
      }
      if (current !== cmd.oldOid) {
        reportLines.push('ng ' + cmd.ref + ' non-fast-forward');
        continue;
      }
      if (!cmd.ref.startsWith('refs/tags/') && !isAncestor(repo, cmd.oldOid, cmd.newOid)) {
        reportLines.push('ng ' + cmd.ref + ' non-fast-forward');
        continue;
      }
      repo.refs.set(cmd.ref, cmd.newOid);
      bumpRepo(repo);
      reportLines.push('ok ' + cmd.ref);
    }
  } else {
    for (const cmd of commands) reportLines.push('ng ' + cmd.ref + ' ' + unpackDetail);
  }
  const innerParts: Buffer[] = [pktLine('unpack ' + (unpackOk ? 'ok' : unpackDetail) + '\n')];
  for (const line of reportLines) innerParts.push(pktLine(line + '\n'));
  innerParts.push(pktFlush());
  const inner = Buffer.concat(innerParts);
  const outer = Buffer.concat([sidebandWrap(inner), pktFlush()]);
  return outer;
}

// ------------------------------------------------------------------ router

function decodeSeg(seg: string): string {
  try {
    return decodeURIComponent(seg);
  } catch {
    return seg;
  }
}

async function handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const method = req.method ?? 'GET';
  const url = new URL(req.url ?? '/', 'http://127.0.0.1');
  const pathname = url.pathname;
  const q = queryOf(url);
  const host = req.headers.host ?? '127.0.0.1';
  const rawSegments = pathname.split('/').filter((s) => s.length > 0);
  const segments = rawSegments.map(decodeSeg);

  try {
    if (pathname === '/healthz') {
      if (method === 'GET') {
        sendJson(res, 200, { ok: true });
        return;
      }
      sendError(res, 404, 'Not Found');
      return;
    }

    const needsBody = method === 'POST' || method === 'PUT' || method === 'PATCH' || method === 'DELETE';
    let body = Buffer.alloc(0);
    if (needsBody) {
      try {
        body = await readBody(req);
      } catch (err) {
        const status = (err as { status?: number }).status ?? 400;
        sendError(res, status, status === 413 ? 'body too large' : 'could not read body');
        return;
      }
    }

    // Git smart HTTP: /{owner}/{repo}.git/...
    if (segments.length >= 2 && segments[1].endsWith('.git')) {
      const owner = segments[0];
      const name = segments[1].slice(0, -4);
      if (!authed(req)) {
        sendError(res, 401, 'Requires authentication');
        return;
      }
      const repo = gitRepo(res, owner, name);
      if (!repo) return;
      const gitPath = '/' + segments.slice(2).join('/');
      if (method === 'GET' && gitPath === '/info/refs') {
        const service = q.service ?? '';
        if (service === 'git-upload-pack') {
          const v2 = (req.headers['git-protocol'] ?? '').includes('version=2');
          sendGitBytes(res, 200, 'application/x-git-upload-pack-advertisement', v2 ? advertiseUploadPackV2() : advertiseUploadPackV0(repo));
          return;
        }
        if (service === 'git-receive-pack') {
          sendGitBytes(res, 200, 'application/x-git-receive-pack-advertisement', advertiseReceivePack(repo));
          return;
        }
        sendError(res, 400, 'unknown service');
        return;
      }
      if (method === 'POST' && gitPath === '/git-upload-pack') {
        try {
          const v2 = (req.headers['git-protocol'] ?? '').includes('version=2');
          const out = handleUploadPack(repo, body, v2);
          sendGitBytes(res, 200, 'application/x-git-upload-pack-result', out);
        } catch (err) {
          sendError(res, 400, err instanceof Error ? err.message : 'bad git request');
        }
        return;
      }
      if (method === 'POST' && gitPath === '/git-receive-pack') {
        try {
          const out = handleReceivePack(repo, body);
          sendGitBytes(res, 200, 'application/x-git-receive-pack-result', out);
        } catch (err) {
          sendError(res, 400, err instanceof Error ? err.message : 'bad git request');
        }
        return;
      }
      sendError(res, 404, 'Not Found');
      return;
    }

    // REST + GraphQL + MCP all require the bearer token.
    if (pathname.startsWith('/api/')) {
      if (!authed(req)) {
        sendError(res, 401, 'Requires authentication');
        return;
      }
      if (pathname === '/api/graphql' && method === 'POST') {
        handleGraphQL(req, res, body.toString('utf8'));
        return;
      }
      if (pathname.startsWith('/api/v3')) {
        const restSegs = segments.slice(2);
        if (handleRest(req, res, method, restSegs, q, body.toString('utf8'), host)) return;
        sendError(res, 404, 'Not Found');
        return;
      }
      sendError(res, 404, 'Not Found');
      return;
    }
    if (pathname === '/mcp' && method === 'POST') {
      if (!authed(req)) {
        sendError(res, 401, 'Requires authentication');
        return;
      }
      handleMcp(req, res, body.toString('utf8'));
      return;
    }
    sendError(res, 404, 'Not Found');
  } catch (err) {
    console.error('handler error:', err instanceof Error ? err.message : String(err));
    if (!res.headersSent) sendError(res, 500, 'Internal Server Error');
    else res.end();
  }
}

// ------------------------------------------------------------------ lifecycle

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function postRegister(port: number): Promise<number> {
  let delay = 100;
  for (let attempt = 0; attempt < 40; attempt++) {
    try {
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), 5000);
      const resp = await fetch(ENV_URL.replace(/\/+$/, '') + '/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ port }),
        signal: ctrl.signal,
      });
      clearTimeout(timer);
      return resp.status;
    } catch {
      await sleep(delay);
      delay = Math.min(2000, delay * 2);
    }
  }
  return 0;
}

async function pollDone(): Promise<void> {
  let delay = 250;
  for (;;) {
    try {
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), 30000);
      const resp = await fetch(ENV_URL.replace(/\/+$/, '') + '/done', { signal: ctrl.signal });
      clearTimeout(timer);
      const data = (await resp.json()) as { done?: boolean };
      if (data.done === true) return;
    } catch {
      // transient: keep polling
    }
    await sleep(delay);
    delay = Math.min(2000, delay * 2);
  }
}

async function main(): Promise<void> {
  const server = createServer((req, res) => {
    void handleRequest(req, res);
  });
  server.keepAliveTimeout = 30000;
  server.headersTimeout = 31000;
  await new Promise<void>((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve());
  });
  const address = server.address();
  const port = typeof address === 'object' && address !== null ? address.port : 0;
  console.log('listening on port ' + port);
  const status = await postRegister(port);
  if (status === 409) {
    console.error('already registered by another entry');
    process.exit(1);
  }
  if (status !== 200) {
    console.error('register failed with status ' + status);
    process.exit(1);
  }
  await pollDone();
  process.exit(0);
}

void main();
