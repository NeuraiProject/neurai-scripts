import type { Cursor } from '../../core/script-parser.js';
import type { ScriptBuilder } from '../../core/script-builder.js';
import type { PartialFillExpiration } from '../../types.js';
export declare function assertExpiration(expiration: PartialFillExpiration | undefined): PartialFillExpiration | undefined;
export declare function appendExpirationGate(b: ScriptBuilder, expiration: PartialFillExpiration | undefined): void;
export declare function readOptionalExpirationGate(c: Cursor, nextOpcodeWithoutGate: number, label: string): PartialFillExpiration | undefined;
export declare function assertSameExpiration(a: PartialFillExpiration | undefined, b: PartialFillExpiration | undefined, label: string): void;
