/*
 * memfs.js — 浏览器/WKWebView 内的内存文件系统适配器
 *
 * 接口与 src/hostfs-node.js 完全一致，供 GuestProcess 的 syscall 层使用。
 * Swift 侧在启动时把应用沙盒内预置的文件读出来，构造 files 映射注入，
 * 之后所有文件 syscall 都在 JS 内同步完成 —— 绕开 WKScriptMessageHandler
 * 只能异步、无法同步返回值的限制。写操作留在内存，退出时可整体回传 Swift。
 *
 * 依赖：TextEncoder/TextDecoder（WKWebView 内置）。
 */

'use strict';

(function (global) {
    const S_IFMT = 0o170000, S_IFREG = 0o100000, S_IFDIR = 0o040000;
    const DT_DIR = 4, DT_REG = 8;
    const AT_FDCWD = -100;

    function normalize(p) {
        const parts = [];
        for (const seg of String(p).split('/')) {
            if (!seg || seg === '.') continue;
            if (seg === '..') { parts.pop(); continue; }
            parts.push(seg);
        }
        return '/' + parts.join('/');
    }

    /**
     * @param {object} files  路径 -> Uint8Array|string 的初始文件映射
     *   e.g. { '/etc/version': 'WASMJIT\n', '/home/x/a.bin': new Uint8Array([...]) }
     */
    function createMemFS(files = {}) {
        const encoder = new TextEncoder();
        const nodes = new Map(); // path -> { bytes: Uint8Array, dir: false }
        const dirs = new Set(['/']);

        for (const [rawPath, content] of Object.entries(files)) {
            const p = normalize(rawPath);
            const bytes = typeof content === 'string' ? encoder.encode(content)
                        : content instanceof Uint8Array ? content
                        : new Uint8Array(content);
            nodes.set(p, { bytes, dir: false });
            // 补齐父目录
            const segs = p.split('/').filter(Boolean);
            let acc = '';
            for (let i = 0; i < segs.length - 1; i++) {
                acc += '/' + segs[i];
                dirs.add(acc);
            }
        }

        function isDir(p) { return p === '/' || dirs.has(p); }
        function parentOf(p) { return p.slice(0, p.lastIndexOf('/')) || '/'; }

        function statObj(node, p) {
            const size = node ? node.bytes.length : 0;
            const mode = (isDir(p) ? S_IFDIR : S_IFREG) | 0o644;
            return {
                dev: 1, ino: 1, mode, nlink: 1, uid: 0, gid: 0, rdev: 0,
                size, blksize: 4096, blocks: Math.ceil(size / 512),
                atime: 0, atimeNs: 0, mtime: 0, mtimeNs: 0, ctime: 0, ctimeNs: 0,
            };
        }

        return {
            AT_FDCWD,

            openat(dirHandle, p, flags, mode) {
                const full = normalize((p.startsWith('/') || !dirHandle)
                    ? p : dirHandle.guestPath + '/' + p);
                const isDirPath = isDir(full);
                const node = nodes.get(full);
                if (!isDirPath && !node) {
                    // O_CREAT(0x40)：允许创建
                    if ((Number(flags) & 0x40) === 0) return -2; // ENOENT
                    nodes.set(full, { bytes: new Uint8Array(0), dir: false });
                }
                return {
                    kind: 'file', guestPath: full, dir: isDirPath,
                    pos: 0, node: nodes.get(full) || null,
                };
            },

            read(handle, len) {
                if (handle.dir) return -21;
                const bytes = handle.node ? handle.node.bytes : new Uint8Array(0);
                const end = Math.min(handle.pos + len, bytes.length);
                const out = bytes.slice(handle.pos, end);
                handle.pos = end;
                return out;
            },

            write(handle, bytes) {
                if (handle.dir) return -21;
                if (!handle.node) return -9;
                const cur = handle.node.bytes;
                const need = handle.pos + bytes.length;
                if (need > cur.length) {
                    const grown = new Uint8Array(need);
                    grown.set(cur);
                    handle.node.bytes = grown;
                }
                handle.node.bytes.set(bytes, handle.pos);
                handle.pos += bytes.length;
                return bytes.length;
            },

            close() { return 0; },

            lseek(handle, offset, whence) {
                let base = whence === 0 ? 0 : whence === 1 ? handle.pos
                         : whence === 2 ? (handle.node ? handle.node.bytes.length : 0) : -1;
                if (base < 0) return -22;
                const np = base + Number(offset);
                if (np < 0) return -22;
                handle.pos = np;
                return np;
            },

            fstat(handle) { return statObj(handle.node, handle.guestPath); },

            getdents(handle) {
                if (!handle.dir) return -20;
                const prefix = handle.guestPath === '/' ? '' : handle.guestPath;
                const seen = new Set();
                const out = [];
                const consider = (p) => {
                    if (!p.startsWith(prefix + '/')) return;
                    const rest = p.slice(prefix.length + 1);
                    if (!rest || rest.includes('/')) return;
                    if (seen.has(rest)) return;
                    seen.add(rest);
                    out.push({ ino: 1, off: out.length + 1,
                               type: isDir(p) ? DT_DIR : DT_REG, name: rest });
                };
                for (const p of dirs) consider(p);
                for (const p of nodes.keys()) consider(p);
                const res = out.slice(handle.dirPos || 0);
                handle.dirPos = (handle.dirPos || 0) + res.length;
                return res;
            },

            getcwd() { return '/'; },
            chdir() { return -20; },

            /** 导出当前内存文件树，供 Swift 在退出后取回写入结果 */
            snapshot() {
                const out = {};
                for (const [p, node] of nodes) out[p] = Array.from(node.bytes);
                return out;
            },

            constants: { S_IFMT, S_IFREG, S_IFDIR, AT_FDCWD },
        };
    }

    global.createMemFS = createMemFS;
})(typeof window !== 'undefined' ? window : globalThis);
