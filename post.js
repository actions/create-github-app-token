// @ts-check

import core from "@actions/core";

import { post } from "./lib/post.js";
import request from "./lib/request.js";

post(
  core,
  request.defaults({
    baseUrl: process.env["GITHUB_API_URL"],
  })
).catch((error) => {
  /* c8 ignore next 3 */
  console.error(error);
  core.setFailed(error.message);
});
