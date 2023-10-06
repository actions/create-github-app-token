import { readFileSync } from "node:fs";
import * as url from "node:url";
import YAML from "yaml";

const action = YAML.parse(
  readFileSync(
    url.fileURLToPath(new URL("../action.yml", import.meta.url)),
    "utf8"
  )
);

for (const [key, value] of Object.entries(action.inputs)) {
  if ("deprecationMessage" in value) {
    console.log(`${key} — ${value.deprecationMessage}`);
  }
}
