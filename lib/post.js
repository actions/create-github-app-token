// @ts-check

import core from "@actions/core";
import { request } from "@octokit/request";

request.defaults({
  baseUrl: process.env["GITHUB_API_URL"],
});

/**
 * @param {core} core
 * @param {request} request
 */
export async function post(core, request) {
  const token = core.getState("token");

  if (!token) return;

  await request("DELETE /installation/token", {
    headers: {
      authorization: `token ${token}`,
    },
  });

  core.info("Token revoked");
}
