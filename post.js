// @ts-check

import core from "@actions/core";
import { request } from "@octokit/request";

import { post } from "./lib/post.js";

post(core, request).catch(
  (error) => {
    console.error(error);
    core.setFailed(error.message);
  }
);
