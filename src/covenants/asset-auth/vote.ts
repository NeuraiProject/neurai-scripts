/**
 * NIP-054 vote lock: a wallet template (not part of the opcode) that holds a
 * role's owner token while it votes for a proposal.
 *
 * The holder sends the owner token, with the proposal hash H as its transfer
 * message, to the generic AuthScript v1 (NoAuth) address of this script:
 *
 *   OP_IF                                     execute, up to height T
 *     OP_1 OP_CHAINCONTEXT <T> OP_LESSTHANOREQUAL OP_VERIFY
 *     OP_SWAP OP_4 OP_INPUTFIELD <0x01 || C> OP_EQUALVERIFY
 *     OP_OUTPUTSCRIPT <return> OP_EQUAL
 *   OP_ELSE                                   give it back, after T
 *     OP_1 OP_CHAINCONTEXT <T> OP_GREATERTHAN OP_VERIFY
 *     OP_NIP OP_OUTPUTSCRIPT <return> OP_EQUAL
 *   OP_ENDIF
 *
 * Both branches send the token back to its owner (`return`, the full output
 * script). The execute branch also needs the custody, commitment C, at the
 * input it names. It must use OP_INPUTFIELD selector 04, the full
 * version-plus-commitment: selector 02 only reads the first 34 bytes of the
 * spent script, which a forged anyone-can-spend custody can match.
 */

import { hexToBytes, concatBytes } from '../../core/bytes.js';
import {
  CHAINCONTEXT_HEIGHT,
  OP_CHAINCONTEXT,
  OP_ELSE,
  OP_ENDIF,
  OP_EQUAL,
  OP_EQUALVERIFY,
  OP_GREATERTHAN,
  OP_IF,
  OP_INPUTFIELD,
  OP_LESSTHANOREQUAL,
  OP_NIP,
  OP_OUTPUTSCRIPT,
  OP_SWAP,
  OP_VERIFY
} from '../../core/opcodes.js';
import { encodeScriptNum, ScriptBuilder } from '../../core/script-builder.js';

/** OP_INPUTFIELD selector: the full version-plus-commitment of the spent script. */
const INPUTFIELD_AUTHSCRIPT_DESTINATION = 0x04;
const AUTHSCRIPT_V1 = 0x01;

export interface AssetAuthVoteLockParams {
  /** Expiry height of the proposal the vote is for. */
  T: number;
  /** 32-byte AuthScript commitment C of the custody, as in its scriptPubKey `OP_1 <C>` (hex or bytes). */
  custodyCommitment: string | Uint8Array;
  /** The output script that gives the owner token back to its holder (hex or bytes). */
  returnScriptPubKey: string | Uint8Array;
}

function asBytes(value: string | Uint8Array): Uint8Array {
  return typeof value === 'string' ? hexToBytes(value) : value;
}

function assertIndex(name: string, value: number): void {
  if (!Number.isInteger(value) || value < 0 || value > 0x7fffffff) {
    throw new Error(`${name} must be an integer from 0 to ${0x7fffffff}`);
  }
}

export function buildAssetAuthVoteLockScript(params: AssetAuthVoteLockParams): Uint8Array {
  assertIndex('T', params.T);
  const commitment = asBytes(params.custodyCommitment);
  if (commitment.length !== 32) {
    throw new Error(`custodyCommitment must be 32 bytes (got ${commitment.length})`);
  }
  const returnScript = asBytes(params.returnScriptPubKey);
  if (returnScript.length === 0) {
    throw new Error('returnScriptPubKey must not be empty');
  }
  return new ScriptBuilder()
    .op(OP_IF)
    .pushInt(CHAINCONTEXT_HEIGHT).op(OP_CHAINCONTEXT).pushInt(params.T).op(OP_LESSTHANOREQUAL, OP_VERIFY)
    .op(OP_SWAP).pushInt(INPUTFIELD_AUTHSCRIPT_DESTINATION).op(OP_INPUTFIELD)
    .pushBytes(concatBytes(Uint8Array.of(AUTHSCRIPT_V1), commitment)).op(OP_EQUALVERIFY)
    .op(OP_OUTPUTSCRIPT).pushBytes(returnScript).op(OP_EQUAL)
    .op(OP_ELSE)
    .pushInt(CHAINCONTEXT_HEIGHT).op(OP_CHAINCONTEXT).pushInt(params.T).op(OP_GREATERTHAN, OP_VERIFY)
    .op(OP_NIP, OP_OUTPUTSCRIPT).pushBytes(returnScript).op(OP_EQUAL)
    .op(OP_ENDIF)
    .build();
}

/**
 * Witness `args` of the execute branch: the index of the custody input and
 * the index of the output that returns the token.
 */
export function buildAssetAuthVoteExecuteArgs(params: { custodyInput: number; returnOutput: number }): Uint8Array[] {
  assertIndex('custodyInput', params.custodyInput);
  assertIndex('returnOutput', params.returnOutput);
  return [encodeScriptNum(params.custodyInput), encodeScriptNum(params.returnOutput), encodeScriptNum(1)];
}

/** Witness `args` of the return branch, after T. */
export function buildAssetAuthVoteReturnArgs(params: { returnOutput: number }): Uint8Array[] {
  assertIndex('returnOutput', params.returnOutput);
  return [encodeScriptNum(0), encodeScriptNum(params.returnOutput), encodeScriptNum(0)];
}
