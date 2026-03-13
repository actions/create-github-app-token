import { readdirSync } from "node:fs";

import test from "ava";
import { execa } from "execa";

// Get all files in tests directory
const files = readdirSync("tests");

// Files to ignore
const ignore = ["index.js", "main.js", "README.md", "snapshots"];

const testFiles = files.filter((file) => !ignore.includes(file));

// Throw an error if there is a file that does not end with test.js in the tests directory
for (const file of testFiles) {
  if (!file.endsWith(".test.js")) {
    throw new Error(`File ${file} does not end with .test.js`);
  }
  test(file, async (t) => {
    // Override Actions environment variables that change `core`’s behavior
    const env = {
      GITHUB_OUTPUT: undefined,
      GITHUB_STATE: undefined,
      HTTP_PROXY: undefined,
      HTTPS_PROXY: undefined,
      http_proxy: undefined,
      https_proxy: undefined,
      NO_PROXY: undefined,
      no_proxy: undefined,
      NODE_OPTIONS: undefined,
      NODE_USE_ENV_PROXY: undefined,
    };
    const { stderr, stdout } = await execa("node", [`tests/${file}`], { env });
    t.snapshot(stderr, "stderr");
    t.snapshot(stdout, "stdout");
  });
}
