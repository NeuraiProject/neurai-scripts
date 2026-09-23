import { dts } from 'rollup-plugin-dts';

// CommonJS declarations for the `require` entry (dist/index.cjs). tsc emits
// ESM declarations ("type": "module"), which a CommonJS consumer resolving
// with moduleResolution node16 cannot use (TS1471). The same declarations are
// bundled into dist/index.d.cts.
export default {
  input: './dist/index.d.ts',
  output: { file: './dist/index.d.cts', format: 'es' },
  external: (id) => !id.startsWith('.') && !id.startsWith('/'),
  plugins: [dts()]
};
