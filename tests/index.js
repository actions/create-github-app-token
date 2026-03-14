import { readdirSync } from "node:fs";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

import { snapshot, test } from "node:test";

const execFileAsync = promisify(execFile);

// Serialize strings as-is so multiline output is human-readable in snapshots
snapshot.setDefaultSnapshotSerializers([
  (value) => (typeof value === "string" ? value : undefined),
]);

// Get all files in tests directory
const files = readdirSync("tests");

// Files to ignore
const ignore = ["index.js", "index.js.snapshot", "main.js", "README.md"];

const testFiles = files.filter((file) => !ignore.includes(file)).sort();

// Throw an error if there is a file that does not end with test.js in the tests directory
for (const file of testFiles) {
  if (!file.endsWith(".test.js")) {
    throw new Error(`File ${file} does not end with .test.js`);
  }
  test(file, async (t) => {
    // Override Actions environment variables that change `core`’s behavior
    const {
      GITHUB_OUTPUT,
      GITHUB_STATE,
      HTTP_PROXY,
      HTTPS_PROXY,
      http_proxy,
      https_proxy,
      NO_PROXY,
      no_proxy,
      NODE_OPTIONS,
      NODE_USE_ENV_PROXY,
      ...env
    } = process.env;
    const { stderr, stdout } = await execFileAsync("node", [`tests/${file}`], {
      env,
    });
    const trimmedStderr = stderr.replace(/\r?\n$/, "");
    const trimmedStdout = stdout.replace(/\r?\n$/, "");
    await t.test("stderr", (t) => {
      if (trimmedStderr) t.assert.snapshot(trimmedStderr);
      else t.assert.strictEqual(trimmedStderr, "");
    });
    await t.test("stdout", (t) => {
      if (trimmedStdout) t.assert.snapshot(trimmedStdout);
      else t.assert.strictEqual(trimmedStdout, "");
    });
  });
}
