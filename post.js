// @ts-check

import core from "@actions/core";
import { request } from "@octokit/request";

import { post } from "./lib/post.js";

post(
  core,
  request.defaults({
    baseUrl: process.env["GITHUB_API_URL"],
  })
).catch((error) => {
  console.error(error);
  core.setFailed(error.message);
});
