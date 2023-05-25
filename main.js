// @ts-check

import core from "@actions/core";
import { App } from "octokit";

// we export the `main` function for testing.
// Call `main()` directly if this file is the entry point
if (import.meta.url.endsWith(process.argv[1])) {
  if (!process.env.GITHUB_REPOSITORY) {
    throw new Error(
      "GITHUB_REPOSITORY missing, must be set to '<owner>/<repo>'"
    );
  }

  const app = new App({
    appId: core.getInput("app_id"),
    privateKey: core.getInput("private_key"),
  });

  const repository = process.env.GITHUB_REPOSITORY;

  main(app, repository, core).catch((error) => {
    console.error(error);
    core.setFailed(error.message);
  });
}

/**
 * @param {App} app
 * @param {string} repository
 * @param {core} core
 */
export async function main(app, repository, core) {
  // Get owner and repo name from GITHUB_REPOSITORY
  const [owner, repo] = repository.split("/");

  // Get the installation ID
  // https://docs.github.com/en/rest/apps/apps?apiVersion=2022-11-28#get-a-repository-installation-for-the-authenticated-app
  const { data: installation } = await app.octokit.request(
    "GET /repos/{owner}/{repo}/installation",
    {
      owner,
      repo,
    }
  );

  // Create Octokit instance
  const octokit = await app.getInstallationOctokit(installation.id);

  // Create a new installation token
  const authentication = await octokit.auth({
    type: "installation",
    installationId: installation.id,
    repositoryNames: [repo],
  });

  // @ts-expect-error
  core.setOutput("token", authentication.token)

  // Make token accessible to post function (so we can invalidate it)
  // @ts-expect-error
  core.saveState("token", authentication.token);

}
