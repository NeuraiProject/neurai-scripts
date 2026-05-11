import { CHAINCONTEXT_HEIGHT, CHAINCONTEXT_MTP, OP_CHAINCONTEXT, OP_GREATERTHAN, OP_VERIFY } from '../../core/opcodes.js';
import { expectByte, readPushPositiveInt, readPushUint8 } from '../../core/script-parser.js';
const MAX_INT64 = 0x7fffffffffffffffn;
function selectorForMode(mode) {
    if (mode === 'height')
        return CHAINCONTEXT_HEIGHT;
    if (mode === 'mtp')
        return CHAINCONTEXT_MTP;
    throw new Error('expiration.mode must be "height" or "mtp"');
}
function modeForSelector(selector) {
    if (selector === CHAINCONTEXT_HEIGHT)
        return 'height';
    if (selector === CHAINCONTEXT_MTP)
        return 'mtp';
    throw new Error('expiration OP_CHAINCONTEXT selector must be HEIGHT (0x01) or MTP (0x02)');
}
export function assertExpiration(expiration) {
    if (expiration === undefined)
        return undefined;
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
export function appendExpirationGate(b, expiration) {
    if (!expiration)
        return;
    // Selectors 1 (HEIGHT) and 2 (MTP) must be pushed as OP_1 / OP_2 so the
    // resulting script is consensus-minimal (MINIMALDATA). `pushBytes(0x01 N)`
    // would emit `01 0N`, which the consensus rule rejects for N in 1..16.
    // Parser side stays lenient (`readPushUint8` accepts both forms) so old
    // covenants in the raw `01 0N` form keep round-tripping.
    b.pushInt(expiration.value)
        .pushInt(selectorForMode(expiration.mode))
        .op(OP_CHAINCONTEXT, OP_GREATERTHAN, OP_VERIFY);
}
export function readOptionalExpirationGate(c, nextOpcodeWithoutGate, label) {
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
export function assertSameExpiration(a, b, label) {
    if (a === undefined && b === undefined)
        return;
    if (a === undefined || b === undefined || a.mode !== b.mode || a.value !== b.value) {
        throw new Error(`parse: expiration differs between ${label}`);
    }
}
