// Verify that `main.js` rejects when the child process exits with a non-zero code.
import assert from "node:assert";
import { mock } from "node:test";

mock.module("node:child_process", {
  namedExports: {
    spawn() {
      return {
        on(event, callback) {
          if (event === "exit") callback(1);
        },
      };
    },
  },
});

process.env.GITHUB_REPOSITORY = "actions/create-github-app-token";
process.env.GITHUB_REPOSITORY_OWNER = "actions";
process.env.https_proxy = "http://proxy.example.com";
delete process.env.NODE_USE_ENV_PROXY;

const { default: runPromise } = await import("../main.js");

await assert.rejects(runPromise, {
  message: "Child process exited with code 1",
});
assert.equal(process.exitCode, 1, "process exit code is 1");

// Reset for other tests
process.exitCode = 0;
