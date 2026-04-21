import * as NeuraiScripts from '../index.js';

const globalTarget = globalThis as typeof globalThis & {
  NeuraiScripts?: typeof NeuraiScripts;
};

globalTarget.NeuraiScripts = NeuraiScripts;

export { NeuraiScripts };
