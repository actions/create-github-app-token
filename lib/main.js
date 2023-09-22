// @ts-check

/**
 * @param {string} appId
 * @param {string} privateKey
 * @param {string} owner
 * @param {string} repositories
 * @param {import("@actions/core")} core
 * @param {import("@octokit/auth-app").createAppAuth} createAppAuth
 * @param {import("@octokit/request").request} request
 */
export async function main(
  appId,
  privateKey,
  owner,
  repositories,
  core,
  createAppAuth,
  request
) {

  let org = "";
  if (owner.length == 0) {
    org = process.env.GITHUB_REPOSITORY_OWNER || "";
  }

  if (owner.length == 0 && repositories.length == 0) {
    repositories = process.env.GITHUB_REPOSITORY?.split("/")[1] || "";
  }

  let repos = [];
  if (repositories.trim() != "") {
    repos = repositories.split(",").map((repo) => repo.trim());
  }

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
    "GET /orgs/{org}/installation",
    {
      org,
      headers: {
        authorization: `bearer ${appAuthentication.token}`,
      },
    }
  );

  // Create a new installation token
  let authentication;

  if (repositories.length == 0) {
    authentication = await auth({
      type: "installation",
      installationId: installation.id,
    });
  } else {
    authentication = await auth({
      type: "installation",
      installationId: installation.id,
      repositoryNames: repos,
    });
  }
  
  // Register the token with the runner as a secret to ensure it is masked in logs
  core.setSecret(authentication.token);

  core.setOutput("token", authentication.token);

  // Make token accessible to post function (so we can invalidate it)
  core.saveState("token", authentication.token);
}
