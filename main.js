// @ts-check

import core from "@actions/core";
import { createAppAuth } from "@octokit/auth-app";
import { request } from "@octokit/request";

import { main } from "./lib/main.js";

if (!process.env.GITHUB_REPOSITORY) {
  throw new Error("GITHUB_REPOSITORY missing, must be set to '<owner>/<repo>'");
}

const appId = core.getInput("app_id");
const privateKey = core.getInput("private_key");

const repository = process.env.GITHUB_REPOSITORY;

main(appId, privateKey, repository, core, createAppAuth, request).catch(
  (error) => {
    console.error(error);
    core.setFailed(error.message);
  }
);
