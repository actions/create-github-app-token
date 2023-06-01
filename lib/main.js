// @ts-check

import core from "@actions/core";
import { createAppAuth } from "@octokit/auth-app";
import { request } from "@octokit/request";

/**
 * @param {string} appId
 * @param {string} privateKey
 * @param {string} repository
 * @param {core} core
 * @param {createAppAuth} createAppAuth
 * @param {request} request
 */
export async function main(
    appId,
    privateKey,
    repository,
    core,
    createAppAuth,
    request
  ) {
    // Get owner and repo name from GITHUB_REPOSITORY
    const [owner, repo] = repository.split("/");

    const auth = createAppAuth({
      appId,
      privateKey,
    });

    const appAuthentication = await auth({
      type: "app",
    });

    // Get the installation ID
    // https://docs.github.com/en/rest/apps/apps?apiVersion=2022-11-28#get-a-repository-installation-for-the-authenticated-app
    const { data: installation } = await request(
      "GET /repos/{owner}/{repo}/installation",
      {
        owner,
        repo,
        headers: {
          authorization: `bearer ${appAuthentication.token}`,
        },
      }
    );

    // Create a new installation token
    const authentication = await auth({
      type: "installation",
      installationId: installation.id,
      repositoryNames: [repo],
    });

    core.setOutput("token", authentication.token);

    // Make token accessible to post function (so we can invalidate it)
    core.saveState("token", authentication.token);
  }
