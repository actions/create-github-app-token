import { readdirSync } from "node:fs";

import { execa } from "execa";
import test from "ava";

const tests = readdirSync("tests").filter((file) => file.endsWith(".test.js"));

for (const file of tests) {
  test(file, async (t) => {
    const { stderr, stdout } = await execa("node", [`tests/${file}`]);
    t.snapshot(stderr, "stderr");
    t.snapshot(stdout, "stdout");
  });
}
