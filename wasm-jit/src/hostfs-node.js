/*
 * hostfs-node.js — Node 宿主的文件系统适配器
 *
 * 把 guest 的 Linux 路径映射到宿主真实文件系统（rootfs 沙箱），
 * 供 syscalls.js 的 openat/read/write/lseek/fstat/getdents64 等使用。
 * iOS 侧提供同样接口的另一实现（内存 fs，Swift 注入/回写），
 * syscall 逻辑本身完全共用。
 */

'use strict';

const fs = require('fs');
const path = require('path');

const AT_FDCWD = -100;

// 文件类型位（st_mode 高 16 位）
const S_IFMT = 0o170000;
const S_IFREG = 0o100000;
const S_IFDIR = 0o040000;
const S_IFLNK = 0o120000;
const S_IFCHR = 0o020000;
const S_IFBLK = 0o060000;
const S_IFIFO = 0o010000;
const S_IFSOCK = 0o140000;

// dirent d_type
const DT_UNKNOWN = 0, DT_FIFO = 1, DT_CHR = 2, DT_DIR = 4,
      DT_BLK = 6, DT_REG = 8, DT_LNK = 10, DT_SOCK = 12;

const NODE_ERRNO = {
    ENOENT: -2, EPERM: -1, EACCES: -13, EBADF: -9, EEXIST: -17,
    ENOTDIR: -20, EISDIR: -21, EINVAL: -22, ENOSPC: -28,
    ELOOP: -40, ENAMETOOLONG: -36, ENOTEMPTY: -39, EIO: -5,
};

function errnoOf(ex) {
    return (ex && NODE_ERRNO[ex.code]) || -5;
}

/**
 * @param {string|null} rootfs  宿主 rootfs 根目录；null 表示直接用宿主根
 * @param {string} cwd          guest 初始工作目录（绝对路径，默认 '/'）
 */
function createNodeFS(rootfs, cwd) {
    const rootResolved = rootfs ? path.resolve(rootfs) : null;
    let guestCwd = cwd || '/';

    /** guest 路径 -> 宿主路径，阻止 ../ 逃逸 rootfs */
    function toHost(p, dirHandle) {
        if (typeof p !== 'string') return { err: -22 };
        if (!p.startsWith('/')) {
            const base = (dirHandle && dirHandle.guestPath) || guestCwd;
            p = path.posix.resolve(base, p);
        }
        p = path.posix.normalize(p);
        if (!rootResolved) return { guest: p, host: p };
        const rel = p.replace(/^\/+/, '');
        const host = path.resolve(rootResolved, rel);
        if (host !== rootResolved && !host.startsWith(rootResolved + path.sep)) {
            return { guest: p, err: -13 }; // EACCES: 逃逸
        }
        return { guest: p, host };
    }

    function modeOf(st) {
        const m = st.mode;
        const kind = m & S_IFMT;
        const t = (kind === S_IFDIR) ? S_IFDIR : (kind === S_IFLNK) ? S_IFLNK
                : (kind === S_IFCHR) ? S_IFCHR : (kind === S_IFBLK) ? S_IFBLK
                : (kind === S_IFIFO) ? S_IFIFO : (kind === S_IFSOCK) ? S_IFSOCK : S_IFREG;
        return (t | (m & 0o777)) >>> 0;
    }

    function dtoType(st) {
        const kind = st.mode & S_IFMT;
        if (kind === S_IFDIR) return DT_DIR;
        if (kind === S_IFLNK) return DT_LNK;
        if (kind === S_IFCHR) return DT_CHR;
        if (kind === S_IFBLK) return DT_BLK;
        if (kind === S_IFIFO) return DT_FIFO;
        if (kind === S_IFSOCK) return DT_SOCK;
        return DT_REG;
    }

    function statObj(st) {
        const ns = st.mtimeNs !== undefined ? st.mtimeNs : Math.floor(st.mtimeMs % 1000) * 1e6;
        const as = st.atimeNs !== undefined ? st.atimeNs : Math.floor(st.atimeMs % 1000) * 1e6;
        const cs = st.ctimeNs !== undefined ? st.ctimeNs : Math.floor(st.ctimeMs % 1000) * 1e6;
        return {
            dev: 1, ino: Number(st.ino) >>> 0,
            mode: modeOf(st), nlink: st.nlink || 1,
            uid: st.uid || 0, gid: st.gid || 0, rdev: 0,
            size: Number(st.size),
            blksize: st.blksize || 4096,
            blocks: Math.ceil(Number(st.size) / 512),
            atime: Math.floor(st.atimeMs / 1000), atimeNs: as,
            mtime: Math.floor(st.mtimeMs / 1000), mtimeNs: ns,
            ctime: Math.floor(st.ctimeMs / 1000), ctimeNs: cs,
        };
    }

    return {
        AT_FDCWD,

        /**
         * 返回 handle 对象（成功）或负数 errno（失败）。
         * @param {object|null} dirHandle  AT_FDCWD 传 null，否则为已打开的目录 handle
         */
        openat(dirHandle, p, flags, mode) {
            const r = toHost(p, dirHandle);
            if (r.err) return r.err;
            // Linux flags 与 Node fs.constants 的数值一致，直接透传
            try {
                const fd = fs.openSync(r.host, Number(flags) | fs.constants.O_CLOEXEC,
                                       Number(mode) || 0o666);
                const st = fs.fstatSync(fd);
                return {
                    kind: 'file', fd, pos: 0,
                    guestPath: r.guest, hostPath: r.host,
                    dir: Boolean(modeOf(st) & S_IFDIR),
                };
            } catch (ex) {
                return errnoOf(ex);
            }
        },

        read(handle, len) {
            try {
                if (handle.dir) return -21; // EISDIR
                const buf = Buffer.allocUnsafe(len);
                const n = fs.readSync(handle.fd, buf, 0, len, handle.pos);
                if (n > 0) handle.pos += n;
                return buf.subarray(0, Math.max(n, 0));
            } catch (ex) { return errnoOf(ex); }
        },

        write(handle, bytes) {
            try {
                if (handle.dir) return -21;
                let off = 0;
                while (off < bytes.length) {
                    const n = fs.writeSync(handle.fd, bytes, off, bytes.length - off, handle.pos);
                    if (n <= 0) break;
                    off += n; handle.pos += n;
                }
                return off;
            } catch (ex) { return errnoOf(ex); }
        },

        close(handle) {
            try { fs.closeSync(handle.fd); return 0; }
            catch (ex) { return errnoOf(ex); }
        },

        /** whence: 0=SEEK_SET 1=SEEK_CUR 2=SEEK_END */
        lseek(handle, offset, whence) {
            try {
                if (handle.dir) {
                    // 目录句柄：用预读的 entry 数模拟 Seek，getdents64 用 dirPos
                    if (whence === 0) handle.dirPos = offset;
                    else if (whence === 1) handle.dirPos = (handle.dirPos || 0) + offset;
                    else return -22;
                    return handle.dirPos;
                }
                let base;
                if (whence === 0) base = 0;
                else if (whence === 1) base = handle.pos;
                else if (whence === 2) base = Number(fs.fstatSync(handle.fd).size);
                else return -22;
                const np = base + Number(offset);
                if (np < 0) return -22;
                handle.pos = np;
                return np;
            } catch (ex) { return errnoOf(ex); }
        },

        fstat(handle) {
            try { return statObj(fs.fstatSync(handle.fd)); }
            catch (ex) { return errnoOf(ex); }
        },

        /** 返回 [{ino, off, type, name}] 或负数 errno */
        getdents(handle) {
            try {
                if (!handle.dir) return -20; // ENOTDIR
                if (!handle._entries) {
                    const names = fs.readdirSync(handle.hostPath);
                    handle._entries = names.map((name, i) => {
                        const st = fs.lstatSync(path.join(handle.hostPath, name));
                        return { ino: Number(st.ino) >>> 0, off: i + 1,
                                 type: dtoType(st), name };
                    });
                }
                const out = handle._entries.slice(handle.dirPos || 0);
                handle.dirPos = (handle.dirPos || 0) + out.length;
                return out;
            } catch (ex) { return errnoOf(ex); }
        },

        getcwd() { return guestCwd; },
        chdir(dirHandle) {
            if (!dirHandle || !dirHandle.dir) return -20;
            guestCwd = dirHandle.guestPath;
            return 0;
        },

        constants: { S_IFMT, S_IFREG, S_IFDIR, S_IFLNK, AT_FDCWD },
    };
}

module.exports = { createNodeFS, AT_FDCWD };
