import type { MemFS } from './vfs-memfs';

const dec = new TextDecoder();
const enc = new TextEncoder();

export interface TarBuildEntry {
  path: string;
  type: 'file' | 'dir' | 'symlink';
  data?: string | Uint8Array;
  target?: string;
  mode?: number;
}

function readStr(buf: Uint8Array, off: number, len: number): string {
  let end = off;
  const max = off + len;
  while (end < max && buf[end] !== 0) end++;
  return dec.decode(buf.subarray(off, end));
}

function readOctal(buf: Uint8Array, off: number, len: number): number {
  const s = readStr(buf, off, len).trim();
  return s ? parseInt(s, 8) : 0;
}

function writeStr(buf: Uint8Array, off: number, len: number, str: string): void {
  const bytes = enc.encode(str);
  buf.set(bytes.subarray(0, Math.min(len, bytes.length)), off);
}

function writeOctal(buf: Uint8Array, off: number, len: number, val: number): void {
  const s = val.toString(8).padStart(len - 1, '0');
  writeStr(buf, off, len - 1, s);
  buf[off + len - 1] = 0;
}

export function extractTarToMemFS(tarBytes: Uint8Array | ArrayBuffer, memfs: MemFS): number {
  const u8 = tarBytes instanceof Uint8Array ? tarBytes : new Uint8Array(tarBytes);
  let offset = 0;
  let pendingLongName: string | null = null;
  let pendingLongLink: string | null = null;
  let extractedCount = 0;

  while (offset + 512 <= u8.length) {
    let allZero = true;
    for (let i = 0; i < 512; i++) {
      if (u8[offset + i] !== 0) {
        allZero = false;
        break;
      }
    }
    if (allZero) break;

    const name = readStr(u8, offset, 100);
    const mode = readOctal(u8, offset + 100, 8) & 0o777;
    const size = readOctal(u8, offset + 124, 12);
    const typeFlag = String.fromCharCode(u8[offset + 156] || 48);
    const linkName = readStr(u8, offset + 157, 100);
    const prefix = readStr(u8, offset + 345, 155);

    const dataStart = offset + 512;
    const dataEnd = dataStart + size;
    const nextOffset = dataStart + ((size + 511) & ~511);

    if (typeFlag === 'L') {
      pendingLongName = readStr(u8, dataStart, size);
      offset = nextOffset;
      continue;
    }
    if (typeFlag === 'K') {
      pendingLongLink = readStr(u8, dataStart, size);
      offset = nextOffset;
      continue;
    }

    let fullPath = pendingLongName || (prefix ? `${prefix}/${name}` : name);
    const targetLink = pendingLongLink || linkName;
    pendingLongName = null;
    pendingLongLink = null;

    fullPath = fullPath.replace(/^\.\//, '/').replace(/^\/+/, '/');
    if (!fullPath.startsWith('/')) fullPath = '/' + fullPath;
    if (fullPath.length > 1 && fullPath.endsWith('/')) fullPath = fullPath.slice(0, -1);

    if (typeFlag === '5') {
      memfs.mkdirp(fullPath);
      extractedCount++;
    } else if (typeFlag === '2') {
      memfs.symlink(targetLink, fullPath);
      extractedCount++;
    } else if (typeFlag === '1') {
      const absTarget = targetLink.startsWith('/') ? targetLink : '/' + targetLink.replace(/^\.\//, '');
      memfs.symlink(absTarget, fullPath);
      extractedCount++;
    } else if (typeFlag === '0' || typeFlag === '\0') {
      memfs.writeFile(fullPath, u8.subarray(dataStart, dataEnd), mode || 0o644);
      extractedCount++;
    }

    offset = nextOffset;
  }

  return extractedCount;
}

export function buildTar(entries: TarBuildEntry[]): Uint8Array {
  const blocks: Uint8Array[] = [];
  for (const e of entries) {
    const hdr = new Uint8Array(512);
    const cleanPath = e.path.replace(/^\/+/, '');
    writeStr(hdr, 0, 100, cleanPath);
    writeOctal(hdr, 100, 8, e.mode ?? (e.type === 'dir' ? 0o755 : 0o644));
    writeOctal(hdr, 108, 8, 0);
    writeOctal(hdr, 116, 8, 0);
    const payload =
      e.type === 'file'
        ? typeof e.data === 'string'
          ? enc.encode(e.data)
          : (e.data ? new Uint8Array(e.data) : new Uint8Array(0))
        : new Uint8Array(0);
    writeOctal(hdr, 124, 12, payload.length);
    writeOctal(hdr, 136, 12, Math.floor(Date.now() / 1000));
    hdr.fill(32, 148, 156);
    hdr[156] = e.type === 'dir' ? 53 : e.type === 'symlink' ? 50 : 48;
    if (e.type === 'symlink') writeStr(hdr, 157, 100, e.target || '');
    writeStr(hdr, 257, 6, 'ustar');
    writeStr(hdr, 263, 2, '00');

    let sum = 0;
    for (let i = 0; i < 512; i++) sum += hdr[i];
    writeOctal(hdr, 148, 7, sum);
    hdr[155] = 32;

    blocks.push(hdr);
    if (payload.length > 0) {
      const padded = new Uint8Array((payload.length + 511) & ~511);
      padded.set(payload, 0);
      blocks.push(padded);
    }
  }
  blocks.push(new Uint8Array(1024));
  const total = blocks.reduce((acc, b) => acc + b.length, 0);
  const out = new Uint8Array(total);
  let pos = 0;
  for (const b of blocks) {
    out.set(b, pos);
    pos += b.length;
  }
  return out;
}
