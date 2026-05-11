import {
  CHAINCONTEXT_HEIGHT,
  CHAINCONTEXT_MTP,
  OP_CHAINCONTEXT,
  OP_GREATERTHAN,
  OP_VERIFY
} from '../../core/opcodes.js';
import type { Cursor } from '../../core/script-parser.js';
import {
  expectByte,
  readPushPositiveInt,
  readPushUint8
} from '../../core/script-parser.js';
import type { ScriptBuilder } from '../../core/script-builder.js';
import type {
  PartialFillExpiration,
  PartialFillExpirationMode
} from '../../types.js';

const MAX_INT64 = 0x7fffffffffffffffn;

function selectorForMode(mode: PartialFillExpirationMode): number {
  if (mode === 'height') return CHAINCONTEXT_HEIGHT;
  if (mode === 'mtp') return CHAINCONTEXT_MTP;
  throw new Error('expiration.mode must be "height" or "mtp"');
}

function modeForSelector(selector: number): PartialFillExpirationMode {
  if (selector === CHAINCONTEXT_HEIGHT) return 'height';
  if (selector === CHAINCONTEXT_MTP) return 'mtp';
  throw new Error('expiration OP_CHAINCONTEXT selector must be HEIGHT (0x01) or MTP (0x02)');
}

export function assertExpiration(
  expiration: PartialFillExpiration | undefined
): PartialFillExpiration | undefined {
  if (expiration === undefined) return undefined;
  if (expiration === null || typeof expiration !== 'object') {
    throw new Error('expiration must be an object');
  }
  selectorForMode(expiration.mode);
  if (typeof expiration.value !== 'bigint') {
    throw new Error('expiration.value must be a bigint');
  }
  if (expiration.value <= 0n) {
    throw new Error('expiration.value must be > 0');
  }
  if (expiration.value > MAX_INT64) {
    throw new Error('expiration.value exceeds int64 range');
  }
  return expiration;
}

export function appendExpirationGate(
  b: ScriptBuilder,
  expiration: PartialFillExpiration | undefined
): void {
  if (!expiration) return;
  b.pushInt(expiration.value)
    .pushBytes(Uint8Array.of(selectorForMode(expiration.mode)))
    .op(OP_CHAINCONTEXT, OP_GREATERTHAN, OP_VERIFY);
}

export function readOptionalExpirationGate(
  c: Cursor,
  nextOpcodeWithoutGate: number,
  label: string
): PartialFillExpiration | undefined {
  if (c.pos >= c.bytes.length || c.bytes[c.pos] === nextOpcodeWithoutGate) {
    return undefined;
  }

  const value = readPushPositiveInt(c, `expiration value (${label})`);
  if (value <= 0n) {
    throw new Error(`parse: expiration value (${label}) must be > 0`);
  }
  const selector = readPushUint8(c, `expiration selector (${label})`);
  const mode = modeForSelector(selector);
  expectByte(c, OP_CHAINCONTEXT, `OP_CHAINCONTEXT (${label})`);
  expectByte(c, OP_GREATERTHAN, `OP_GREATERTHAN (${label})`);
  expectByte(c, OP_VERIFY, `OP_VERIFY (${label})`);

  return { mode, value };
}

export function assertSameExpiration(
  a: PartialFillExpiration | undefined,
  b: PartialFillExpiration | undefined,
  label: string
): void {
  if (a === undefined && b === undefined) return;
  if (a === undefined || b === undefined || a.mode !== b.mode || a.value !== b.value) {
    throw new Error(`parse: expiration differs between ${label}`);
  }
}
