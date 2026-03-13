// Verify that `runWithProxy()` calls the callback directly (no child process)
// when `NODE_USE_ENV_PROXY` is already set to `"1"`, even with proxy env vars set.
import assert from "node:assert";
import { runWithProxy } from "../lib/run-with-proxy.js";

process.env.https_proxy = "http://proxy.example.com";
process.env.NODE_USE_ENV_PROXY = "1";

let callbackCalled = false;

await runWithProxy(async () => {
  callbackCalled = true;
});

assert(callbackCalled, "callback was called directly without spawning");

delete process.env.NODE_USE_ENV_PROXY;
delete process.env.https_proxy;


