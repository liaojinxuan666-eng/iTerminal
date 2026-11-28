(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.WasmEncoderV2 = factory();
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  const VALTYPE = {
    I32: 0x7f,
    I64: 0x7e,
    F32: 0x7d,
    F64: 0x7c,
    FUNCREF: 0x70,
    VOID: 0x40,
  };

  const SECTION = {
    TYPE: 1,
    IMPORT: 2,
    FUNCTION: 3,
    TABLE: 4,
    MEMORY: 5,
    GLOBAL: 6,
    EXPORT: 7,
    ELEMENT: 9,
    CODE: 10,
    DATA: 11,
  };

  const IMPORT_KIND = {
    FUNC: 0x00,
    TABLE: 0x01,
    MEM: 0x02,
    GLOBAL: 0x03,
  };

  const OP = {
    UNREACHABLE: 0x00,
    NOP: 0x01,
    BLOCK: 0x02,
    LOOP: 0x03,
    IF: 0x04,
    ELSE: 0x05,
    END: 0x0b,
    BR: 0x0c,
    BR_IF: 0x0d,
    BR_TABLE: 0x0e,
    RETURN: 0x0f,
    CALL: 0x10,
    CALL_INDIRECT: 0x11,
    DROP: 0x1a,
    SELECT: 0x1b,

    LOCAL_GET: 0x20,
    LOCAL_SET: 0x21,
    LOCAL_TEE: 0x22,
    GLOBAL_GET: 0x23,
    GLOBAL_SET: 0x24,

    I32_LOAD: 0x28,
    I64_LOAD: 0x29,
    I32_LOAD8_S: 0x2c,
    I32_LOAD8_U: 0x2d,
    I32_LOAD16_S: 0x2e,
    I32_LOAD16_U: 0x2f,
    I64_LOAD8_S: 0x30,
    I64_LOAD8_U: 0x31,
    I64_LOAD16_S: 0x32,
    I64_LOAD16_U: 0x33,
    I64_LOAD32_S: 0x34,
    I64_LOAD32_U: 0x35,
    I32_STORE: 0x36,
    I64_STORE: 0x37,
    I32_STORE8: 0x3a,
    I32_STORE16: 0x3b,
    I64_STORE8: 0x3c,
    I64_STORE16: 0x3d,
    I64_STORE32: 0x3e,

    I32_CONST: 0x41,
    I64_CONST: 0x42,

    I32_EQZ: 0x45,
    I32_EQ: 0x46,
    I32_NE: 0x47,
    I32_LT_S: 0x48,
    I32_LT_U: 0x49,
    I32_GT_S: 0x4a,
    I32_GT_U: 0x4b,
    I32_LE_S: 0x4c,
    I32_LE_U: 0x4d,
    I32_GE_S: 0x4e,
    I32_GE_U: 0x4f,

    I64_EQZ: 0x50,
    I64_EQ: 0x51,
    I64_NE: 0x52,
    I64_LT_S: 0x53,
    I64_LT_U: 0x54,
    I64_GT_S: 0x55,
    I64_GT_U: 0x56,
    I64_LE_S: 0x57,
    I64_LE_U: 0x58,
    I64_GE_S: 0x59,
    I64_GE_U: 0x5a,

    I32_ADD: 0x6a,
    I32_SUB: 0x6b,
    I32_MUL: 0x6c,
    I32_AND: 0x71,
    I32_OR: 0x72,
    I32_XOR: 0x73,
    I32_SHL: 0x74,
    I32_SHR_S: 0x75,
    I32_SHR_U: 0x76,

    I64_ADD: 0x7c,
    I64_SUB: 0x7d,
    I64_MUL: 0x7e,
    I64_DIV_S: 0x7f,
    I64_DIV_U: 0x80,
    I64_REM_S: 0x81,
    I64_REM_U: 0x82,
    I64_AND: 0x83,
    I64_OR: 0x84,
    I64_XOR: 0x85,
    I64_SHL: 0x86,
    I64_SHR_S: 0x87,
    I64_SHR_U: 0x88,
    I64_ROTR: 0x8a,

    I32_WRAP_I64: 0xa7,
    I64_EXTEND_I32_S: 0xac,
    I64_EXTEND_I32_U: 0xad,
  };

  function uleb128(value) {
    const out = [];
    let v = value >>> 0;
    do {
      let byte = v & 0x7f;
      v >>>= 7;
      if (v !== 0) byte |= 0x80;
      out.push(byte);
    } while (v !== 0);
    return out;
  }

  function sleb128(value) {
    const out = [];
    let v = typeof value === 'bigint' ? value : BigInt(value);
    let more = true;
    while (more) {
      let byte = Number(v & 0x7fn);
      v >>= 7n;
      const signBit = (byte & 0x40) !== 0;
      if ((v === 0n && !signBit) || (v === -1n && signBit)) {
        more = false;
      } else {
        byte |= 0x80;
      }
      out.push(byte);
    }
    return out;
  }

  function encodeStr(str) {
    const bytes = new TextEncoder().encode(str);
    return [...uleb128(bytes.length), ...bytes];
  }

  function encodeVec(items) {
    const out = uleb128(items.length);
    for (const item of items) {
      for (let i = 0; i < item.length; i++) out.push(item[i]);
    }
    return out;
  }

  function encodeSection(id, payload) {
    if (!payload || payload.length === 0) return [];
    return [id, ...uleb128(payload.length), ...payload];
  }

  function encodeFuncType(params, results) {
    return [0x60, ...uleb128(params.length), ...params, ...uleb128(results.length), ...results];
  }

  function encodeLimits(min, max) {
    if (max === undefined || max === null) {
      return [0x00, ...uleb128(min)];
    }
    return [0x01, ...uleb128(min), ...uleb128(max)];
  }

  function encodeCodeBody(locals, body) {
    const localDecls = [];
    for (const [count, type] of locals) {
      localDecls.push([...uleb128(count), type]);
    }
    const raw = [...encodeVec(localDecls), ...body, OP.END];
    return [...uleb128(raw.length), ...raw];
  }

  class ModuleBuilder {
    constructor() {
      this.types = [];
      this.imports = [];
      this.funcs = [];
      this.exports = [];
      this.codes = [];
    }

    addType(params, results) {
      const idx = this.types.length;
      this.types.push(encodeFuncType(params, results));
      return idx;
    }

    importFunc(mod, name, typeIdx) {
      const idx = this.imports.filter((x) => x.kind === IMPORT_KIND.FUNC).length;
      this.imports.push({
        kind: IMPORT_KIND.FUNC,
        bytes: [...encodeStr(mod), ...encodeStr(name), IMPORT_KIND.FUNC, ...uleb128(typeIdx)],
      });
      return idx;
    }

    importMemory(mod, name, min, max) {
      this.imports.push({
        kind: IMPORT_KIND.MEM,
        bytes: [...encodeStr(mod), ...encodeStr(name), IMPORT_KIND.MEM, ...encodeLimits(min, max)],
      });
    }

    importTable(mod, name, min, max) {
      this.imports.push({
        kind: IMPORT_KIND.TABLE,
        bytes: [
          ...encodeStr(mod),
          ...encodeStr(name),
          IMPORT_KIND.TABLE,
          VALTYPE.FUNCREF,
          ...encodeLimits(min, max),
        ],
      });
    }

    addFunction(typeIdx, locals, body, exportName) {
      const importedFuncs = this.imports.filter((x) => x.kind === IMPORT_KIND.FUNC).length;
      const funcIdx = importedFuncs + this.funcs.length;
      this.funcs.push(uleb128(typeIdx));
      this.codes.push(encodeCodeBody(locals, body));
      if (exportName) {
        this.exports.push([...encodeStr(exportName), IMPORT_KIND.FUNC, ...uleb128(funcIdx)]);
      }
      return funcIdx;
    }

    toUint8Array() {
      const bytes = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
      const push = (arr) => {
        for (let i = 0; i < arr.length; i++) bytes.push(arr[i]);
      };
      if (this.types.length) push(encodeSection(SECTION.TYPE, encodeVec(this.types)));
      if (this.imports.length) {
        push(encodeSection(SECTION.IMPORT, encodeVec(this.imports.map((x) => x.bytes))));
      }
      if (this.funcs.length) push(encodeSection(SECTION.FUNCTION, encodeVec(this.funcs)));
      if (this.exports.length) push(encodeSection(SECTION.EXPORT, encodeVec(this.exports)));
      if (this.codes.length) push(encodeSection(SECTION.CODE, encodeVec(this.codes)));
      return new Uint8Array(bytes);
    }
  }

  return {
    VALTYPE,
    SECTION,
    IMPORT_KIND,
    OP,
    uleb128,
    sleb128,
    encodeStr,
    encodeVec,
    encodeSection,
    encodeFuncType,
    encodeLimits,
    encodeCodeBody,
    ModuleBuilder,
  };
});
