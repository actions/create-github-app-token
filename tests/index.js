import { readdirSync } from "node:fs";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

import { snapshot, test } from "node:test";

const execFileAsync = promisify(execFile);

// Serialize strings as-is so multiline output is human-readable in snapshots
snapshot.setDefaultSnapshotSerializers([
  (value) => (typeof value === "string" ? value : value),
]);

// Get all files in tests directory
const files = readdirSync("tests");

// Files to ignore
const ignore = ["index.js", "index.js.snapshot", "main.js", "README.md"];

const testFiles = files.filter((file) => !ignore.includes(file));

// Throw an error if there is a file that does not end with test.js in the tests directory
for (const file of testFiles) {
  if (!file.endsWith(".test.js")) {
    throw new Error(`File ${file} does not end with .test.js`);
  }
  test(file, async (t) => {
    // Override Actions environment variables that change `core`’s behavior
    const env = {
      ...process.env,
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
    // Remove keys set to undefined since execFile passes env as-is
    for (const key of Object.keys(env)) {
      if (env[key] === undefined) delete env[key];
    }
    const { stderr, stdout } = await execFileAsync("node", [`tests/${file}`], {
      env,
    });
    // Strip trailing newline to match execa's default behavior
    const trimmedStderr = stderr.replace(/\n$/, "");
    const trimmedStdout = stdout.replace(/\n$/, "");
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
