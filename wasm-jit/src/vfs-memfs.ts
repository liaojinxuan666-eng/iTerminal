export const S_IFREG = 0o100000;
export const S_IFDIR = 0o040000;
export const S_IFLNK = 0o120000;
export const DT_DIR = 4;
export const DT_REG = 8;
export const DT_LNK = 10;

export interface StatResult {
  ino: number;
  mode: number;
  size: number;
  mtime: number;
  isDir: boolean;
  isSymlink: boolean;
}

export interface DirEntry {
  name: string;
  ino: number;
  type: number;
}

type VFSNode =
  | { type: 'dir'; ino: number; mode: number; mtime: number }
  | { type: 'file'; ino: number; mode: number; data: Uint8Array; mtime: number }
  | { type: 'symlink'; ino: number; mode: number; target: string; mtime: number };

interface SerializedEntry {
  path: string;
  type: 'dir' | 'file' | 'symlink';
  mode?: number;
  target?: string;
  data?: number[];
}

export function normalizePath(p: string, cwd = '/'): string {
  const raw = p.startsWith('/') ? p : `${cwd.replace(/\/+$/, '')}/${p}`;
  const parts: string[] = [];
  for (const seg of raw.split('/')) {
    if (!seg || seg === '.') continue;
    if (seg === '..') parts.pop();
    else parts.push(seg);
  }
  return '/' + parts.join('/');
}

export class MemFS {
  private nextIno = 2;
  private nodes = new Map<string, VFSNode>();

  constructor() {
    const now = Math.floor(Date.now() / 1000);
    this.nodes.set('/', {
      type: 'dir',
      ino: 1,
      mode: S_IFDIR | 0o755,
      mtime: now,
    });
  }

  mkdirp(dirPath: string): void {
    const norm = normalizePath(dirPath);
    if (norm === '/') return;
    const segs = norm.slice(1).split('/');
    let cur = '';
    for (const s of segs) {
      cur += '/' + s;
      if (!this.nodes.has(cur)) {
        this.nodes.set(cur, {
          type: 'dir',
          ino: this.nextIno++,
          mode: S_IFDIR | 0o755,
          mtime: Math.floor(Date.now() / 1000),
        });
      }
    }
  }

  writeFile(filePath: string, data: string | Uint8Array, mode = 0o644): void {
    const norm = normalizePath(filePath);
    const parent = norm.slice(0, norm.lastIndexOf('/')) || '/';
    this.mkdirp(parent);
    const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : new Uint8Array(data);
    const existing = this.nodes.get(norm);
    this.nodes.set(norm, {
      type: 'file',
      ino: existing ? existing.ino : this.nextIno++,
      mode: S_IFREG | mode,
      data: bytes,
      mtime: Math.floor(Date.now() / 1000),
    });
  }

  symlink(target: string, linkPath: string): void {
    const norm = normalizePath(linkPath);
    const parent = norm.slice(0, norm.lastIndexOf('/')) || '/';
    this.mkdirp(parent);
    this.nodes.set(norm, {
      type: 'symlink',
      ino: this.nextIno++,
      mode: S_IFLNK | 0o777,
      target,
      mtime: Math.floor(Date.now() / 1000),
    });
  }

  readlink(linkPath: string, cwd = '/'): string | null {
    const norm = normalizePath(linkPath, cwd);
    const node = this.nodes.get(norm);
    if (!node || node.type !== 'symlink') return null;
    return node.target;
  }

  resolveSymlinks(filePath: string, cwd = '/', maxHops = 16): string {
    let cur = normalizePath(filePath, cwd);
    for (let i = 0; i < maxHops; i++) {
      const node = this.nodes.get(cur);
      if (!node || node.type !== 'symlink') return cur;
      const parent = cur.slice(0, cur.lastIndexOf('/')) || '/';
      cur = normalizePath(node.target, parent);
    }
    return cur;
  }

  readFile(filePath: string, cwd = '/'): Uint8Array | null {
    const resolved = this.resolveSymlinks(filePath, cwd);
    const node = this.nodes.get(resolved);
    if (!node || node.type !== 'file') return null;
    return node.data;
  }

  stat(filePath: string, cwd = '/', followSymlinks = true): StatResult | null {
    const norm = followSymlinks
      ? this.resolveSymlinks(filePath, cwd)
      : normalizePath(filePath, cwd);
    const node = this.nodes.get(norm);
    if (!node) return null;
    return {
      ino: node.ino,
      mode: node.mode,
      size: node.type === 'file' ? node.data.length : node.type === 'symlink' ? node.target.length : 4096,
      mtime: node.mtime,
      isDir: node.type === 'dir',
      isSymlink: node.type === 'symlink',
    };
  }

  listDir(dirPath: string, cwd = '/'): DirEntry[] | null {
    const norm = this.resolveSymlinks(dirPath, cwd);
    const node = this.nodes.get(norm);
    if (!node || node.type !== 'dir') return null;
    const prefix = norm === '/' ? '/' : norm + '/';
    const entries: DirEntry[] = [
      { name: '.', ino: node.ino, type: DT_DIR },
      { name: '..', ino: 1, type: DT_DIR },
    ];
    for (const [k, v] of this.nodes.entries()) {
      if (k === norm || !k.startsWith(prefix)) continue;
      const rest = k.slice(prefix.length);
      if (rest.includes('/')) continue;
      entries.push({
        name: rest,
        ino: v.ino,
        type: v.type === 'dir' ? DT_DIR : v.type === 'symlink' ? DT_LNK : DT_REG,
      });
    }
    return entries;
  }

  rename(oldPath: string, newPath: string, cwd = '/'): boolean {
    const src = normalizePath(oldPath, cwd);
    const dst = normalizePath(newPath, cwd);
    const node = this.nodes.get(src);
    if (!node) return false;
    this.nodes.delete(src);
    this.nodes.set(dst, node);
    return true;
  }

  unlink(filePath: string, cwd = '/'): boolean {
    const norm = normalizePath(filePath, cwd);
    if (norm === '/' || !this.nodes.has(norm)) return false;
    this.nodes.delete(norm);
    return true;
  }

  serialize(): string {
    const entries: SerializedEntry[] = [];
    for (const [path, node] of this.nodes.entries()) {
      if (path === '/') continue;
      if (node.type === 'dir') {
        entries.push({ path, type: 'dir', mode: node.mode });
      } else if (node.type === 'symlink') {
        entries.push({ path, type: 'symlink', target: node.target });
      } else if (node.type === 'file') {
        entries.push({ path, type: 'file', mode: node.mode, data: Array.from(node.data) });
      }
    }
    return JSON.stringify({ version: 1, entries });
  }

  static deserialize(jsonStr: string | { entries?: SerializedEntry[] }): MemFS {
    const fs = new MemFS();
    const parsed = typeof jsonStr === 'string' ? (JSON.parse(jsonStr) as { entries?: SerializedEntry[] }) : jsonStr;
    for (const e of parsed.entries || []) {
      if (e.type === 'dir') fs.mkdirp(e.path);
      else if (e.type === 'symlink') fs.symlink(e.target || '', e.path);
      else if (e.type === 'file') fs.writeFile(e.path, new Uint8Array(e.data || []), (e.mode ?? 0o644) & 0o777);
    }
    return fs;
  }

  static writeAArch64Stat(dv: DataView, ptr: number, st: Pick<StatResult, 'ino' | 'mode' | 'size' | 'mtime'>): void {
    for (let i = 0; i < 128; i += 8) dv.setBigUint64(ptr + i, 0n, true);
    dv.setBigUint64(ptr + 0, 1n, true);
    dv.setBigUint64(ptr + 8, BigInt(st.ino), true);
    dv.setUint32(ptr + 16, st.mode >>> 0, true);
    dv.setUint32(ptr + 20, 1, true);
    dv.setUint32(ptr + 24, 0, true);
    dv.setUint32(ptr + 28, 0, true);
    dv.setBigInt64(ptr + 48, BigInt(st.size), true);
    dv.setInt32(ptr + 56, 4096, true);
    dv.setBigInt64(ptr + 64, BigInt(Math.ceil(st.size / 512)), true);
    dv.setBigInt64(ptr + 72, BigInt(st.mtime), true);
    dv.setBigInt64(ptr + 88, BigInt(st.mtime), true);
    dv.setBigInt64(ptr + 104, BigInt(st.mtime), true);
  }
}
