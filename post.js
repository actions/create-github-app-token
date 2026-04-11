// @ts-check

import * as core from "@actions/core";

import { post } from "./lib/post.js";
import request, { ensureNativeProxySupport } from "./lib/request.js";

async function run() {
  ensureNativeProxySupport();

  return post(core, request);
}

run().catch((error) => {
  /* c8 ignore next 3 */
  console.error(error);
  core.setFailed(error.message);
});
