/**
 * Asset-transfer wrapper split helper.
 *
 * Neurai asset UTXOs have a scriptPubKey of the form
 *
 *     <prefix scriptPubKey bytes> OP_XNA_ASSET <pushdata(payload)> OP_DROP
 *
 * where `prefix` is the recipient's standard script (typically a P2PKH, an
 * AuthScript witness v1, or a bare covenant such as the partial-fill sell
 * order), and `payload` serializes a `CAssetTransfer`:
 *
 *     payload = rvn_prefix (0x72 0x76 0x6e) || type_marker (0x74 transfer)
 *             || VarStr(assetName)
 *             || int64LE(amountRaw)
 *             [ || messageRef (optional) || int64LE(expireTime) (optional) ]
 *
 * This helper separates the two halves so consumers can validate the prefix
 * (e.g. feed it to `parsePartialFillScript`) while independently reading the
 * asset data displayed to the user. The optional payload tail
 * (`message` + `expireTime`) is tolerated but not exposed — the first
 * version only needs `assetName` and `amountRaw`.
 *
 * Bare (non-wrapped) scriptPubKeys round-trip through this helper by
 * returning `prefixHex === input` and `assetTransfer === null`.
 */

import { bytesToHex, hexToBytes, ensureHex } from './core/bytes.js';
import { OP_DROP, OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4, OP_XNA_ASSET } from './core/opcodes.js';

export interface AssetTransferPayload {
  /** ASCII asset name as declared in the VarStr field. */
  assetName: string;
  /** Raw satoshi-scaled amount from the int64LE field. Display units = raw / 1e8. */
  amountRaw: bigint;
  /** Hex of the full payload bytes (starting at the `rvn` magic, ending at
   *  the last byte before OP_DROP). Includes optional tail when present. */
  payloadHex: string;
}

export interface SplitAssetWrappedResult {
  /** Bytes of the scriptPubKey BEFORE the OP_XNA_ASSET wrapper, hex. Equal
   *  to the input when the script carries no asset wrapper. */
  prefixHex: string;
  /** Parsed asset-transfer data, or null if the input has no asset wrapper. */
  assetTransfer: AssetTransferPayload | null;
}

const RVN_MAGIC = Uint8Array.from([0x72, 0x76, 0x6e]); // "rvn"
const TRANSFER_TYPE = 0x74;

/**
 * Walk the script one opcode at a time, skipping pushdata payload bytes,
 * until either OP_XNA_ASSET is reached at top level or the end of the
 * script. Returns the byte offset of OP_XNA_ASSET, or -1 if not found.
 * Throws on truncated pushdata.
 */
function findTopLevelAssetOpcode(bytes: Uint8Array): number {
  let i = 0;
  while (i < bytes.length) {
    const op = bytes[i];
    if (op === OP_XNA_ASSET) return i;

    // Short direct push: 0x01..0x4b
    if (op >= 0x01 && op <= 0x4b) {
      const len = op;
      const next = i + 1 + len;
      if (next > bytes.length) {
        throw new Error(
          `splitAssetWrappedScriptPubKey: short push of ${len} bytes at offset ${i} exceeds script length`
        );
      }
      i = next;
      continue;
    }

    if (op === OP_PUSHDATA1) {
      if (i + 1 >= bytes.length) {
        throw new Error(`splitAssetWrappedScriptPubKey: truncated PUSHDATA1 length at offset ${i}`);
      }
      const len = bytes[i + 1];
      const next = i + 2 + len;
      if (next > bytes.length) {
        throw new Error(
          `splitAssetWrappedScriptPubKey: PUSHDATA1 of ${len} bytes at offset ${i} exceeds script length`
        );
      }
      i = next;
      continue;
    }

    if (op === OP_PUSHDATA2) {
      if (i + 2 >= bytes.length) {
        throw new Error(`splitAssetWrappedScriptPubKey: truncated PUSHDATA2 length at offset ${i}`);
      }
      const len = bytes[i + 1] | (bytes[i + 2] << 8);
      const next = i + 3 + len;
      if (next > bytes.length) {
        throw new Error(
          `splitAssetWrappedScriptPubKey: PUSHDATA2 of ${len} bytes at offset ${i} exceeds script length`
        );
      }
      i = next;
      continue;
    }

    if (op === OP_PUSHDATA4) {
      if (i + 4 >= bytes.length) {
        throw new Error(`splitAssetWrappedScriptPubKey: truncated PUSHDATA4 length at offset ${i}`);
      }
      const len =
        (bytes[i + 1] |
          (bytes[i + 2] << 8) |
          (bytes[i + 3] << 16) |
          (bytes[i + 4] << 24)) >>>
        0;
      const next = i + 5 + len;
      if (next > bytes.length) {
        throw new Error(
          `splitAssetWrappedScriptPubKey: PUSHDATA4 of ${len} bytes at offset ${i} exceeds script length`
        );
      }
      i = next;
      continue;
    }

    // Any other opcode (including OP_1..OP_16, OP_DUP, OP_HASH160, etc.) is
    // one byte wide in Neurai Script. Advance.
    i += 1;
  }
  return -1;
}

/**
 * Read the pushdata element that sits immediately after OP_XNA_ASSET and
 * return its payload bytes together with the cursor position after the
 * element. Only direct pushes (1..75) and PUSHDATA1 are accepted — a
 * well-formed asset transfer payload fits within 75 bytes for the common
 * case and comfortably within 255 bytes even with long names and tails.
 * PUSHDATA2 and PUSHDATA4 would signal a malformed or adversarial wrapper.
 */
function readPayloadPush(bytes: Uint8Array, start: number): { payload: Uint8Array; after: number } {
  if (start >= bytes.length) {
    throw new Error('splitAssetWrappedScriptPubKey: truncated wrapper — missing payload push');
  }
  const op = bytes[start];
  if (op >= 0x01 && op <= 0x4b) {
    const len = op;
    const dataStart = start + 1;
    const dataEnd = dataStart + len;
    if (dataEnd > bytes.length) {
      throw new Error(
        `splitAssetWrappedScriptPubKey: asset payload short push of ${len} bytes exceeds script length`
      );
    }
    return { payload: bytes.slice(dataStart, dataEnd), after: dataEnd };
  }
  if (op === OP_PUSHDATA1) {
    if (start + 1 >= bytes.length) {
      throw new Error('splitAssetWrappedScriptPubKey: truncated PUSHDATA1 in asset payload');
    }
    const len = bytes[start + 1];
    const dataStart = start + 2;
    const dataEnd = dataStart + len;
    if (dataEnd > bytes.length) {
      throw new Error(
        `splitAssetWrappedScriptPubKey: asset payload PUSHDATA1 of ${len} bytes exceeds script length`
      );
    }
    return { payload: bytes.slice(dataStart, dataEnd), after: dataEnd };
  }
  throw new Error(
    `splitAssetWrappedScriptPubKey: asset payload push opcode 0x${op.toString(16)} not accepted (expected 0x01..0x4b or PUSHDATA1)`
  );
}

function parseAssetTransferPayload(payload: Uint8Array): { assetName: string; amountRaw: bigint } {
  if (payload.length < 4 + 1 + 8) {
    // 4 magic+type, 1 varstr length, 8 int64LE amount
    throw new Error(
      `splitAssetWrappedScriptPubKey: asset payload of ${payload.length} bytes is too short`
    );
  }
  for (let i = 0; i < 3; i += 1) {
    if (payload[i] !== RVN_MAGIC[i]) {
      throw new Error(
        `splitAssetWrappedScriptPubKey: asset payload magic mismatch — expected "rvn" got 0x${payload[0].toString(16)} 0x${payload[1].toString(16)} 0x${payload[2].toString(16)}`
      );
    }
  }
  if (payload[3] !== TRANSFER_TYPE) {
    throw new Error(
      `splitAssetWrappedScriptPubKey: asset payload type marker 0x${payload[3].toString(16)} is not a transfer (0x74)`
    );
  }

  const nameLen = payload[4];
  const nameStart = 5;
  const nameEnd = nameStart + nameLen;
  if (nameEnd + 8 > payload.length) {
    throw new Error(
      `splitAssetWrappedScriptPubKey: asset payload truncated — name length ${nameLen} does not leave room for amount`
    );
  }

  let assetName = '';
  for (let i = nameStart; i < nameEnd; i += 1) {
    assetName += String.fromCharCode(payload[i]);
  }

  let amountRaw = 0n;
  for (let i = 0; i < 8; i += 1) {
    amountRaw |= BigInt(payload[nameEnd + i]) << BigInt(8 * i);
  }

  // Any bytes after nameEnd + 8 form the optional tail (message +
  // expireTime). We intentionally ignore them in this first version; the
  // raw payload remains available via `payloadHex` if a consumer later
  // needs to inspect them.
  return { assetName, amountRaw };
}

/**
 * Parse an asset-transfer-wrapped scriptPubKey. Accepts both wrapped and
 * bare forms. Throws on structural malformation (truncated pushdata,
 * missing OP_DROP after payload, bad magic, unsupported pushdata width).
 */
export function splitAssetWrappedScriptPubKey(spkHex: string): SplitAssetWrappedResult {
  const normalized = ensureHex(spkHex, 'scriptPubKey');
  const bytes = hexToBytes(normalized);

  const assetOpAt = findTopLevelAssetOpcode(bytes);
  if (assetOpAt < 0) {
    return { prefixHex: normalized, assetTransfer: null };
  }

  const prefix = bytes.slice(0, assetOpAt);
  const { payload, after } = readPayloadPush(bytes, assetOpAt + 1);

  if (after >= bytes.length) {
    throw new Error('splitAssetWrappedScriptPubKey: asset wrapper missing trailing OP_DROP');
  }
  if (bytes[after] !== OP_DROP) {
    throw new Error(
      `splitAssetWrappedScriptPubKey: expected OP_DROP at offset ${after}, got 0x${bytes[after].toString(16)}`
    );
  }
  if (after + 1 !== bytes.length) {
    throw new Error(
      `splitAssetWrappedScriptPubKey: ${bytes.length - after - 1} trailing bytes after OP_DROP`
    );
  }

  const { assetName, amountRaw } = parseAssetTransferPayload(payload);

  return {
    prefixHex: bytesToHex(prefix),
    assetTransfer: {
      assetName,
      amountRaw,
      payloadHex: bytesToHex(payload),
    },
  };
}
