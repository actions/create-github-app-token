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

let appSettings = core.getInput("app-settings");

let appId;
let privateKey;

if (appSettings) {
  appSettings = JSON.parse(appSettings);
  if (!appSettings['app-id'] || !appSettings['private-key']) {
    throw new Error("app-settings must contain valid app_id and private_key fields");
  }
  appId = appSettings['app-id'];
  privateKey = appSettings['private-key'];
} else {
  appId = core.getInput("app-id") || core.getInput("app_id");
  if (!appId) {
    throw new Error("Input required and not supplied: app-id");
  }

  privateKey = core.getInput("private-key") || core.getInput("private_key");
  if (!privateKey) {
    throw new Error("Input required and not supplied: private-key");
  }
}
const owner = core.getInput("owner");
const repositories = core.getInput("repositories");

const skipTokenRevoke = Boolean(
  core.getInput("skip-token-revoke") || core.getInput("skip_token_revoke")
);

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
