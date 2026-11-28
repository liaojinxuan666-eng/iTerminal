(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.WasmMemFS = factory();
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  const S_IFREG = 0o100000;
  const S_IFDIR = 0o040000;
  const S_IFLNK = 0o120000;
  const DT_DIR = 4;
  const DT_REG = 8;
  const DT_LNK = 10;

  function normalizePath(p, cwd = '/') {
    const raw = p.startsWith('/') ? p : `${cwd.replace(/\/+$/, '')}/${p}`;
    const parts = [];
    for (const seg of raw.split('/')) {
      if (!seg || seg === '.') continue;
      if (seg === '..') parts.pop();
      else parts.push(seg);
    }
    return '/' + parts.join('/');
  }

  /**
   * Self-contained In-Memory POSIX VFS (UMD, zero Node dependencies).
   * Supports regular files, directories, symbolic links (required for BusyBox multi-call
   * applets like `/bin/sh -> /bin/busybox`), and AArch64 Linux ABI `struct stat` (128B).
   */
  class MemFS {
    constructor() {
      this.nextIno = 2;
      this.nodes = new Map();
      const now = Math.floor(Date.now() / 1000);
      this.nodes.set('/', {
        type: 'dir',
        ino: 1,
        mode: S_IFDIR | 0o755,
        mtime: now,
      });
    }

    mkdirp(dirPath) {
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

    writeFile(filePath, data, mode = 0o644) {
      const norm = normalizePath(filePath);
      const parent = norm.slice(0, norm.lastIndexOf('/')) || '/';
      this.mkdirp(parent);
      const bytes =
        typeof data === 'string'
          ? new TextEncoder().encode(data)
          : new Uint8Array(data);
      const existing = this.nodes.get(norm);
      this.nodes.set(norm, {
        type: 'file',
        ino: existing ? existing.ino : this.nextIno++,
        mode: S_IFREG | mode,
        data: bytes,
        mtime: Math.floor(Date.now() / 1000),
      });
    }

    symlink(target, linkPath) {
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

    readlink(linkPath, cwd = '/') {
      const norm = normalizePath(linkPath, cwd);
      const node = this.nodes.get(norm);
      if (!node || node.type !== 'symlink') return null;
      return node.target;
    }

    resolveSymlinks(filePath, cwd = '/', maxHops = 16) {
      let cur = normalizePath(filePath, cwd);
      for (let i = 0; i < maxHops; i++) {
        const node = this.nodes.get(cur);
        if (!node || node.type !== 'symlink') return cur;
        const parent = cur.slice(0, cur.lastIndexOf('/')) || '/';
        cur = normalizePath(node.target, parent);
      }
      return cur;
    }

    readFile(filePath, cwd = '/') {
      const resolved = this.resolveSymlinks(filePath, cwd);
      const node = this.nodes.get(resolved);
      if (!node || node.type !== 'file') return null;
      return node.data;
    }

    stat(filePath, cwd = '/', followSymlinks = true) {
      const norm = followSymlinks
        ? this.resolveSymlinks(filePath, cwd)
        : normalizePath(filePath, cwd);
      const node = this.nodes.get(norm);
      if (!node) return null;
      return {
        ino: node.ino,
        mode: node.mode,
        size:
          node.type === 'file'
            ? node.data.length
            : node.type === 'symlink'
            ? node.target.length
            : 4096,
        mtime: node.mtime,
        isDir: node.type === 'dir',
        isSymlink: node.type === 'symlink',
      };
    }

    listDir(dirPath, cwd = '/') {
      const norm = this.resolveSymlinks(dirPath, cwd);
      const node = this.nodes.get(norm);
      if (!node || node.type !== 'dir') return null;
      const prefix = norm === '/' ? '/' : norm + '/';
      const entries = [
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

    rename(oldPath, newPath, cwd = '/') {
      const src = normalizePath(oldPath, cwd);
      const dst = normalizePath(newPath, cwd);
      const node = this.nodes.get(src);
      if (!node) return false;
      this.nodes.delete(src);
      this.nodes.set(dst, node);
      return true;
    }

    unlink(filePath, cwd = '/') {
      const norm = normalizePath(filePath, cwd);
      if (norm === '/' || !this.nodes.has(norm)) return false;
      this.nodes.delete(norm);
      return true;
    }

    static writeAArch64Stat(dv, ptr, st) {
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

  return { MemFS, normalizePath, S_IFREG, S_IFDIR, S_IFLNK, DT_DIR, DT_REG, DT_LNK };
});
