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

const appId = core.getInput("app-id");
const privateKey = core.getInput("private-key");
const owner = core.getInput("owner");
const repositories = core
  .getInput("repositories")
  .split(/[\n,]+/)
  .map((s) => s.trim())
  .filter((x) => x !== "");

const skipTokenRevoke = Boolean(core.getInput("skip-token-revoke"));

main(
  appId,
  privateKey,
  owner,
  repositories,
  core,
  createAppAuth,
  request,
  skipTokenRevoke
).catch((error) => {
  /* c8 ignore next 3 */
  console.error(error);
  core.setFailed(error.message);
});
