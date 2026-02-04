import { External } from "./napi";
import { libBvisor } from "./libBvisor";

class Stream {
  private ptr: External<"Stream">;

  constructor(ptr: External<"Stream">) {
    this.ptr = ptr;
  }

  toReadableStream(): ReadableStream<Uint8Array> {
    const self = this;
    return new ReadableStream({
      async pull(controller) {
        // TODO: make streamNext return a promise
        const chunk = libBvisor.streamNext(self.ptr);
        if (chunk) {
          controller.enqueue(chunk);
        } else {
          controller.close();
        }
      },
    });
  }
}

export class Sandbox {
  private ptr: External<"Sandbox">;

  constructor() {
    this.ptr = libBvisor.createSandbox();
  }

  runCmd(command: string) {
    const result = libBvisor.sandboxRunCmd(this.ptr, command);
    return createOutput(
      new Stream(result.stdout).toReadableStream(),
      new Stream(result.stderr).toReadableStream()
    );
  }
}

export interface Output {
  stdoutStream: ReadableStream<Uint8Array>;
  stderrStream: ReadableStream<Uint8Array>;
  stdout: () => Promise<string>;
  stderr: () => Promise<string>;
}

function createOutput(
  stdoutStream: ReadableStream<Uint8Array>,
  stderrStream: ReadableStream<Uint8Array>
): Output {
  return {
    stdoutStream,
    stderrStream,
    stdout: () => new Response(stdoutStream).text(),
    stderr: () => new Response(stderrStream).text(),
  };
}
