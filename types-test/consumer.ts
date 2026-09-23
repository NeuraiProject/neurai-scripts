// Compiled by `npm run test:types` against the built package (dist/*.d.ts),
// the way an ESM application imports it, with skipLibCheck: false.
import {
  buildPartialFillScriptPQHex,
  buildStrictWitnessECDSA,
  encodeAuthScriptScriptPubKey,
  encodeSellerScriptPubKey,
  opcodes,
  type AuthScriptWitnessVersion,
  type PartialFillOrderPQParams,
  type SellerScriptPubKey,
} from "@neuraiproject/neurai-scripts";

const version: AuthScriptWitnessVersion = 3;
export const spk: Uint8Array = encodeAuthScriptScriptPubKey(new Uint8Array(32), version);
export const seller: SellerScriptPubKey = encodeSellerScriptPubKey("tnq1rwentz4njukcn400flwk5tu6s8fmzwd3e408nmkqz6dvfysgcdp2suqptef");
export const witness: Uint8Array[] = buildStrictWitnessECDSA({ signature: new Uint8Array(71), pubKey: new Uint8Array(33) });
const params: PartialFillOrderPQParams = {
  paymentAddress: "tpq1z5age5p2v5q9w6qzadkjp4yep8gpr56q6mzd4fu6eus8ntulul6vq3q07pc",
  pubKeyCommitment: new Uint8Array(32),
  tokenId: "CAT",
  unitPriceSats: 1n,
};
export const covenant: string = buildPartialFillScriptPQHex(params);
export const op1: number = opcodes.OP_1;
