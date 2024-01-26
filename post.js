// @ts-check

import core from "@actions/core";

import { post } from "./lib/post.js";
import request from "./lib/request.js";

const baseUrl = core.getInput("github-api-url").replace(/\/$/, "");

post(core, request.defaults({ baseUrl })).catch((error) => {
  /* c8 ignore next 3 */
  console.error(error);
  core.setFailed(error.message);
});
