import { Sandbox } from "./index";

console.log("\n--- runCmd, streaming ---");
const sb = new Sandbox();
const output = sb.runCmd("echo 'Hello, world!'");

const stdoutReader = output.stdoutStream.getReader();
const stderrReader = output.stderrStream.getReader();

console.log("stdout:");

while (true) {
  const chunk = await stdoutReader.read();
  if (chunk.done) {
    break;
  }
  console.log("- chunk: " + new TextDecoder().decode(chunk.value));
}

console.log("\nstderr:");

while (true) {
  const chunk = await stderrReader.read();
  if (chunk.done) {
    break;
  }
  console.log("chunk: " + new TextDecoder().decode(chunk.value));
}

console.log("\n--- runCmd, no streaming ---");
const output2 = sb.runCmd("echo 'Goodbye, world!'");
console.log("stdout: " + (await output2.stdout()));
console.log("stderr: " + (await output2.stderr()));
