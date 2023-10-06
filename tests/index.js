import { readdirSync } from "node:fs";

import { execa } from "execa";
import test from "ava";

const tests = readdirSync("tests").filter((file) => file.endsWith(".test.js"));

for (const file of tests) {
  test(file, async (t) => {
    // Override Actions environment variables that change `core`’s behavior
    const env = {
      GITHUB_OUTPUT: undefined,
      GITHUB_STATE: undefined,
    };
    const { stderr, stdout } = await execa("node", [`tests/${file}`], { env });
    t.snapshot(stderr, "stderr");
    t.snapshot(stdout, "stdout");
  });
}
