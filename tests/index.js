import { readFileSync, readdirSync } from "node:fs";
import * as url from "node:url";

import { execa } from "execa";
import test from "ava";

// If ava is configured to use node arguments, use them when this script runs node
const nodeArguments =
  readFileSync(
    url.fileURLToPath(new URL("../package.json", import.meta.url)),
    "utf8"
  )?.ava?.nodeArguments ?? [];

const tests = readdirSync("tests").filter((file) => file.endsWith(".test.js"));

for (const file of tests) {
  test(file, async (t) => {
    const { stderr, stdout } = await execa("node", [
      ...nodeArguments,
      `tests/${file}`,
    ]);
    t.snapshot(stderr, "stderr");
    t.snapshot(stdout, "stdout");
  });
}
