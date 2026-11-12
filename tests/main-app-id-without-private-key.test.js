import { DEFAULT_ENV } from "./main.js";

for (const [key, value] of Object.entries({
  ...DEFAULT_ENV,
  "INPUT_CLIENT-ID": "",
  "INPUT_APP-ID": "123456",
  "INPUT_PRIVATE-KEY": "",
})) {
  process.env[key] = value;
}

const _error = console.error;
console.error = (err) => _error(err?.message ?? err);

const { default: promise } = await import("../main.js");
await promise;
process.exitCode = 0;