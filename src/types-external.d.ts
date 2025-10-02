// Minimal module declarations for external packages lacking bundled types at build time in this environment.
declare module 'yaml' {
  // Export a parse function returning unknown (caller narrows).
  export function parse(src: string): unknown;
  export function stringify(obj: unknown): string;
  const _default: { parse: typeof parse; stringify: typeof stringify };
  export default _default;
}