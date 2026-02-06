// Phantom-typed opaque handle to a native object.
// N-API "externals" are opaque pointers that JS holds but can't inspect.
// The phantom T prevents accidentally swapping e.g. External<"Sandbox"> and External<"Stream">.
declare const __external: unique symbol;
export type External<T> = unknown & { [__external]: T };
