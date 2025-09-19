import test from "node:test";
import assert from "node:assert";

test("spawns a child process if proxy is set and NODE_USE_ENV_PROXY is not set", async (t) => {
  let spawnCalled = false;

  // https://nodejs.org/api/test.html#class-mocktracker
  t.mock.module("node:child_process", {
    namedExports: {
      spawn() {
        spawnCalled = true;
        return {
          on(event, callback) {
            callback(0);
          },
        };
      },
    },
  });

  process.env.GITHUB_REPOSITORY = "foo/bar";
  process.env.GITHUB_REPOSITORY_OWNER = "foo";
  process.env.https_proxy = "http://example.com";

  const { default: runPromise } = await import("../main.js?" + Math.random());
  await runPromise;

  assert(spawnCalled, "spawn was called");
  assert.equal(process.exitCode, 0, "process exit code is 0");
});

test("child process throws error", async (t) => {
  let spawnCalled = false;

  // https://nodejs.org/api/test.html#class-mocktracker
  t.mock.module("node:child_process", {
    namedExports: {
      spawn() {
        spawnCalled = true;
        return {
          on(event, callback) {
            callback(1);
          },
        };
      },
    },
  });

  process.env.GITHUB_REPOSITORY = "foo/bar";
  process.env.GITHUB_REPOSITORY_OWNER = "foo";
  process.env.https_proxy = "http://example.com";

  const { default: runPromise } = await import("../main.js?" + Math.random());
  await runPromise.catch((error) => {
    assert.equal(
      error.message,
      "Child process exited with code 1",
      "error message is correct",
    );
  });

  assert(spawnCalled, "spawn was called");
  assert.equal(process.exitCode, 1, "process exit code is 0");
  process.exitCode = 0; // reset for other tests
});

test("does not spawn a child process if proxy is set and NODE_USE_ENV_PROXY is set", async (t) => {
  let mainCalled = false;

  t.mock.module("../lib/main.js", {
    namedExports: {
      async main() {
        mainCalled = true;
      },
    },
  });

  process.env.GITHUB_REPOSITORY = "foo/bar";
  process.env.GITHUB_REPOSITORY_OWNER = "foo";
  process.env.https_proxy = "http://example.com";
  process.env.NODE_USE_ENV_PROXY = "1";
  process.env["INPUT_SKIP-TOKEN-REVOKE"] = "false";

  const { default: runPromise } = await import("../main.js?" + Math.random());
  await runPromise;

  assert(mainCalled, "main was called");
});
