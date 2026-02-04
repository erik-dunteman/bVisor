import { arch, platform } from "os";
import { External } from "./napi";

if (platform() !== "linux") {
  throw new Error("bVisor only supports Linux");
}

/** FFI contract: typed interface for the native Zig module loaded via require(). */
export interface LibBvisorModule {
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

export const libBvisor: LibBvisorModule = require(`@bvisor/linux-${arch()}`);
