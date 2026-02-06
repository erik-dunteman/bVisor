import { arch, platform } from "os";
import { familySync, MUSL } from "detect-libc";
import { External } from "./napi";

if (platform() !== "linux") {
  throw new Error("bVisor only supports Linux");
}

/** FFI contract: typed interface for the native Zig module loaded via require(). */
export interface NativeModule {
  createSandbox(): External<"Sandbox">;
  sandboxRunCmd(
    sandbox: External<"Sandbox">,
    command: string
  ): {
    stdout: External<"Stream">;
    stderr: External<"Stream">;
  };
  streamNext(stream: External<"Stream">): Uint8Array | null;
}

const libc = familySync() === MUSL ? "musl" : "gnu";
export const native: NativeModule = require(`@bvisor/linux-${arch()}-${libc}`);
