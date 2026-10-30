/**
 * NIP-054 P2AH custody policy (`OP_CHECKASSETAUTH`, AuthScript only).
 *
 * The policy is the witnessScript of a generic AuthScript v1 (NoAuth)
 * address. A spend of that address needs M of the N owner-token roles of the
 * list to approve it (G of them when an owner token held by the custody
 * leaves it):
 *
 *   policy:  <1> <M> <G> <role_1> ... <role_n> <n> OP_CHECKASSETAUTH
 *   witness: [0x00, <c>, <a>, <b>, <T>, policy]
 *
 * Build the four arguments with `buildAssetAuthArgs` and wrap them with
 * `buildAuthScriptWitnessNoAuth({ args, witnessScript: policy })`. A role
 * approves either by spending its owner token from P2PKH or a strict
 * AuthScript address with a SIGHASH_ALL signature (synchronous spend, every
 * argument 0), or by a vote (see `vote.ts` and `proposal.ts`).
 */

import { OP_1, OP_16, OP_CHECKASSETAUTH } from '../../core/opcodes.js';
import { encodeScriptNum, ScriptBuilder } from '../../core/script-builder.js';
import { makeCursor, readPush, readPushUint8 } from '../../core/script-parser.js';

/** The only policy version defined by NIP-054. */
export const ASSETAUTH_POLICY_VERSION = 1;
/** Highest number of roles in one policy. */
export const ASSETAUTH_MAX_ROLES = 16;
/** c, a, b and T are script numbers of at most 4 bytes. */
const MAX_ARGUMENT = 0x7fffffff;

export interface AssetAuthPolicy {
  /** Roles that must approve a spend. */
  M: number;
  /** Roles that must approve when an owner token held by the custody leaves it (M <= G). */
  G: number;
  /** Owner token names (`NAME!`, `&NAME!`). Any order: the script lists them sorted by bytes. */
  roles: string[];
}

export interface AssetAuthArgs {
  /** Proposal inputs: inputs 0..c-1 are committed by the proposal hash. */
  c: number;
  /** Proposal output prefix: outputs 0..a-1. */
  a: number;
  /** Proposal output suffix: the last b outputs. */
  b: number;
  /** Expiry height of the votes. */
  T: number;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function compareBytes(x: Uint8Array, y: Uint8Array): number {
  const n = Math.min(x.length, y.length);
  for (let i = 0; i < n; i += 1) {
    if (x[i] !== y[i]) return x[i] - y[i];
  }
  return x.length - y.length;
}

/** Role names as the node checks them: sorted by bytes, no duplicates. */
function sortedRoles(roles: string[]): Uint8Array[] {
  if (!Array.isArray(roles) || roles.length < 1 || roles.length > ASSETAUTH_MAX_ROLES) {
    throw new Error(`roles must list 1 to ${ASSETAUTH_MAX_ROLES} owner tokens`);
  }
  const names = roles.map((role) => {
    if (typeof role !== 'string' || !role.endsWith('!')) {
      throw new Error(`role ${JSON.stringify(role)} is not an owner token name (NAME!)`);
    }
    return encoder.encode(role);
  });
  names.sort(compareBytes);
  for (let i = 1; i < names.length; i += 1) {
    if (compareBytes(names[i - 1], names[i]) === 0) {
      throw new Error(`role ${decoder.decode(names[i])} is listed twice`);
    }
  }
  return names;
}

function assertThresholds(M: number, G: number, n: number): void {
  if (!Number.isInteger(M) || !Number.isInteger(G) || M < 1 || M > G || G > n) {
    throw new Error(`thresholds must satisfy 1 <= M <= G <= ${n} (got M=${M}, G=${G})`);
  }
}

export function buildAssetAuthPolicyScript(policy: AssetAuthPolicy): Uint8Array {
  const roles = sortedRoles(policy.roles);
  assertThresholds(policy.M, policy.G, roles.length);
  const b = new ScriptBuilder()
    .pushInt(ASSETAUTH_POLICY_VERSION)
    .pushInt(policy.M)
    .pushInt(policy.G);
  for (const role of roles) b.pushBytes(role);
  return b.pushInt(roles.length).op(OP_CHECKASSETAUTH).build();
}

/** Inverse of `buildAssetAuthPolicyScript`; rejects any other script. */
export function parseAssetAuthPolicyScript(script: Uint8Array): AssetAuthPolicy {
  const end = script.length - 2;
  const nOp = script[end];
  if (script.length < 6 || script[end + 1] !== OP_CHECKASSETAUTH || nOp < OP_1 || nOp > OP_16) {
    throw new Error('parse: not an OP_CHECKASSETAUTH policy script');
  }
  const c = makeCursor(script);
  if (readPushUint8(c, 'version') !== ASSETAUTH_POLICY_VERSION) {
    throw new Error(`parse: policy version must be ${ASSETAUTH_POLICY_VERSION}`);
  }
  const M = readPushUint8(c, 'M');
  const G = readPushUint8(c, 'G');
  const names: Uint8Array[] = [];
  while (c.pos < end) names.push(readPush(c, `role ${names.length + 1}`));
  if (c.pos !== end || names.length !== nOp - OP_1 + 1) {
    throw new Error('parse: role count does not match n');
  }
  const roles = names.map((name) => decoder.decode(name));
  const policy = { M, G, roles };
  // Strictly increasing as written: a re-sorted list would be another script.
  const rebuilt = buildAssetAuthPolicyScript(policy);
  if (compareBytes(rebuilt, script) !== 0) {
    throw new Error('parse: roles are not owner names in strictly increasing byte order');
  }
  return policy;
}

/**
 * Witness `args` [<c>, <a>, <b>, <T>] for the custody input: minimal script
 * numbers, 0 as the empty element. All default to 0, the synchronous spend.
 */
export function buildAssetAuthArgs({ c = 0, a = 0, b = 0, T = 0 }: Partial<AssetAuthArgs> = {}): Uint8Array[] {
  for (const [name, value] of Object.entries({ c, a, b, T })) {
    if (!Number.isInteger(value) || value < 0 || value > MAX_ARGUMENT) {
      throw new Error(`${name} must be an integer from 0 to ${MAX_ARGUMENT}`);
    }
  }
  return [c, a, b, T].map((value) => encodeScriptNum(value));
}
