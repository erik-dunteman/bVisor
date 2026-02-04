# Node SDK

## Layout

```
src/sdks/node/
  index.ts              # Package entry point, re-exports Sandbox
  src/
    libBvisor.ts        # FFI contract: libBvisorModule interface, platform check, require()
    napi.ts             # External<T> phantom type for opaque native handles
    sandbox.ts          # Sandbox class, public API
  test.ts               # Smoke test, run via `npm run dev`
  platforms/
    linux-arm64/        # @bvisor/linux-arm64 package
    linux-x64/          # @bvisor/linux-x64 package
  zig/                  # Zig source for native bindings
    lib.zig             # Entry point, napi module registration
    napi.zig            # N-API helpers, ZigExternal(T)
    Sandbox.zig         # Sandbox implementation
```

## FFI boundary

`src/libBvisor.ts` is the single source of truth for the Zig-TS contract. When adding a new native function: add it to the `LibBvisorModule` interface in `libBvisor.ts`, implement in Zig.

Opaque handles use `External<T>` (defined in `napi.ts`) on the TS side. On the Zig side, `ZigExternal(T)` in `zig/napi.zig` handles wrapping/unwrapping — all JS-facing values are plain `c.napi_value`.

## Build

`zig build` (from project root) cross-compiles native binaries for both linux platforms. The build is defined in the root `build.zig` which loops over aarch64 and x86_64 targets.

`npm run dev` runs `zig build` then executes `test.ts` inside a `oven/bun:alpine` Docker container.

## Platform packages

The `platforms/` subdirectories are npm workspace packages. `npm install` on Linux resolves them locally via workspaces. On macOS, `npm install` will fail due to `os`/`cpu` filtering in the platform package.json files -- use `npm run dev` to build and test in Docker instead.
