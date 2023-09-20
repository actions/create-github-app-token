// @ts-check

import core from "@actions/core";
import { createAppAuth } from "@octokit/auth-app";

import { main } from "./lib/main.js";
import request from "./lib/request.js";

if (!process.env.GITHUB_REPOSITORY) {
  throw new Error("GITHUB_REPOSITORY missing, must be set to '<owner>/<repo>'");
}

const appId = core.getInput("app_id");
const privateKey = core.getInput("private_key");
const owner = core.getInput("owner") || process.env.GITHUB_REPOSITORY.split("/")[0];
const repositories = core.getInput("repositories") || process.env.GITHUB_REPOSITORY.split("/")[1];

main(
  appId,
  privateKey,
  owner,
  repositories,
  core,
  createAppAuth,
  request.defaults({
    baseUrl: process.env["GITHUB_API_URL"],
  })
).catch((error) => {
  console.error(error);
  core.setFailed(error.message);
});
