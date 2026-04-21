/**
 * Provably-unspendable OP_RETURN (null-data) output scripts.
 * Layout: OP_RETURN <push> [<push> ...]
 *
 * Neurai inherits the Bitcoin Core standard policy cap of 80 bytes of
 * payload for a relayed null-data output. Outputs over that cap are still
 * consensus-valid but will not be relayed by default mempool policy; use
 * the `allowNonStandard` option to opt in explicitly.
 */

import { concatBytes } from '../core/bytes.js';
import { pushBytes } from '../core/script-builder.js';
import { OP_RETURN } from '../core/opcodes.js';

export const NULLDATA_STANDARD_MAX_SIZE = 80;

export interface EncodeNullDataOptions {
  /** Bypass the 80-byte standard-policy cap. Default: false. */
  allowNonStandard?: boolean;
}

export function encodeNullDataScript(
  payload: Uint8Array | Uint8Array[],
  options: EncodeNullDataOptions = {}
): Uint8Array {
  const payloads = payload instanceof Uint8Array ? [payload] : payload;
  if (!Array.isArray(payloads) || payloads.length === 0) {
    throw new Error('payload must be a Uint8Array or a non-empty array of Uint8Array');
  }
  let totalPayload = 0;
  for (let i = 0; i < payloads.length; i += 1) {
    const p = payloads[i];
    if (!(p instanceof Uint8Array)) {
      throw new Error(`payload[${i}] must be a Uint8Array`);
    }
    totalPayload += p.length;
  }
  if (!options.allowNonStandard && totalPayload > NULLDATA_STANDARD_MAX_SIZE) {
    throw new Error(
      `nulldata payload of ${totalPayload} bytes exceeds standard cap ${NULLDATA_STANDARD_MAX_SIZE}; set allowNonStandard=true to override`
    );
  }
  const parts: Uint8Array[] = [Uint8Array.of(OP_RETURN)];
  for (const p of payloads) parts.push(pushBytes(p));
  return concatBytes(...parts);
}
