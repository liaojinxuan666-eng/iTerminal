#!/bin/bash
# translate.sh — 把 AArch64 Linux ELF 离线翻译为 WASM 模块
# 用法: bash Scripts/translate.sh <input-elf> [output.wasm]
set -e
DIR="$(cd "$(dirname "$0")/.." && pwd)"
ELF="$1"
OUT="${2:-$DIR/ios-bridge/assets/$(basename "$1" .elf).wasm}"

if [ -z "$ELF" ]; then
  echo "用法: bash Scripts/translate.sh <input-elf> [output.wasm]" >&2
  exit 1
fi

mkdir -p "$(dirname "$OUT")"
node - "$ELF" "$OUT" <<'JS'
const fs = require('fs');
const { translateELF } = require('./src/translator');
const [elf, out] = process.argv.slice(2);
const t = translateELF(elf);
fs.writeFileSync(out, t.binary);
console.log(`翻译完成: ${out}`);
console.log(`  WASM ${t.binary.length} 字节, ${t.blockCount} 个基本块, 入口块 ${t.entryBlock}`);
JS
