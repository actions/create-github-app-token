import test from "node:test";

test("spawns a child process if proxy is set and NODE_USE_ENV_PROXY is not set", async (t) => {
  // https://nodejs.org/api/test.html#class-mocktracker
  // TODO: why u not work
  t.mock.module("node:child_process", {
    namedExports: {
      spawn() {
        throw new Error("----- nope!!! -----");
      },
    },
  });

  process.env.GITHUB_REPOSITORY = "foo/bar";
  process.env.GITHUB_REPOSITORY_OWNER = "foo";
  process.env.https_proxy = "http://example.com";

  await import("../main.js");

  await new Promise((resolve) => setTimeout(resolve, 1000));
});
