// @ts-check

import core from "@actions/core";
import { createAppAuth } from "@octokit/auth-app";

import { main } from "./lib/main.js";
import request from "./lib/request.js";

if (!process.env.GITHUB_REPOSITORY) {
  throw new Error("GITHUB_REPOSITORY missing, must be set to '<owner>/<repo>'");
}

if (!process.env.GITHUB_REPOSITORY_OWNER) {
  throw new Error("GITHUB_REPOSITORY_OWNER missing, must be set to '<owner>'");
}

const appId = core.getInput("app_id");
const privateKey = core.getInput("private_key");
const owner = core.getInput("owner");
const repositories = core.getInput("repositories");

const revoke = core.getInput("revoke") === "true";

main(
  appId,
  privateKey,
  owner,
  repositories,
  core,
  createAppAuth,
  request.defaults({
    baseUrl: process.env["GITHUB_API_URL"],
  }),
  revoke
).catch((error) => {
  console.error(error);
  core.setFailed(error.message);
});
