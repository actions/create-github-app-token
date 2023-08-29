// @ts-check

/**
 * @param {string} appId
 * @param {string} privateKey
 * @param {string} repository
 * @param {import("@actions/core")} core
 * @param {import("@octokit/auth-app").createAppAuth} createAppAuth
 * @param {import("@octokit/request").request} request
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
    request,
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

  // Register the token with the runner as a secret to ensure it is masked in logs
  core.setSecret(authentication.token);

  core.setOutput("token", authentication.token);

  // Make token accessible to post function (so we can invalidate it)
  core.saveState("token", authentication.token);
}
