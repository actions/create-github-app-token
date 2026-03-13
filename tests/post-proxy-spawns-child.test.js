// Verify that `post.js` spawns a child process when a proxy env var is set
// and `NODE_USE_ENV_PROXY` is not set.
import assert from "node:assert";
import { mock } from "node:test";

let spawnArgs;

mock.module("node:child_process", {
  namedExports: {
    spawn(command, args, options) {
      spawnArgs = { command, args, options };
      return {
        on(event, callback) {
          if (event === "exit") callback(0);
        },
      };
    },
  },
});

process.env.https_proxy = "http://proxy.example.com";
delete process.env.NODE_USE_ENV_PROXY;

const { default: runPromise } = await import("../post.js");
await runPromise;

assert(spawnArgs, "spawn was called");
assert.equal(
  spawnArgs.options.env.NODE_USE_ENV_PROXY,
  "1",
  "NODE_USE_ENV_PROXY is set to '1' in child env",
);
assert.equal(spawnArgs.options.stdio, "inherit", "stdio is inherited");
assert.equal(process.exitCode, 0, "process exit code is 0");
