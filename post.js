// @ts-check

import core from "@actions/core";

import { post } from "./lib/post.js";
import request from "./lib/request.js";
import { runWithProxy } from "./lib/run-with-proxy.js";

// Export promise for testing
export default runWithProxy(async () => {
  return post(core, request).catch((error) => {
    /* c8 ignore next 3 */
    console.error(error);
    core.setFailed(error.message);
  });
});
