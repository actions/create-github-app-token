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
  let parsedOwner = "";
  let parsedRepositoryNames = "";

  // if neither owner nor repositories are set, default to current repository
  if (!owner && !repositories) {
    [parsedOwner, parsedRepositoryNames] = String(
      process.env.GITHUB_REPOSITORY
    ).split("/");

    core.info(
      `owner and repositories not set, creating token for the current repository ("${parsedRepositoryNames}")`
    );
  }

  // if only an owner is set, default to all repositories from that owner
  if (owner && !repositories) {
    parsedOwner = owner;

    core.info(
      `repositories not set, creating token for all repositories for given owner "${owner}"`
    );
  }

  // if repositories are set, but no owner, default to `GITHUB_REPOSITORY_OWNER`
  if (!owner && repositories) {
    parsedOwner = String(process.env.GITHUB_REPOSITORY_OWNER);
    parsedRepositoryNames = repositories;

    core.info(
      `owner not set, creating owner for given repositories "${repositories}" in current owner ("${parsedOwner}")`
    );
  }

  // if both owner and repositories are set, use those values
  if (owner && repositories) {
    parsedOwner = owner;
    parsedRepositoryNames = repositories;

    core.info(
      `owner and repositories set, creating token for repositories "${repositories}" owned by "${owner}"`
    );
  }

  const auth = createAppAuth({
    appId,
    privateKey,
    request,
  });

  const appAuthentication = await auth({
    type: "app",
  });

  let authentication;
  // If at least one repository is set, get installation ID from that repository
  // https://docs.github.com/en/rest/apps/apps?apiVersion=2022-11-28#get-a-repository-installation-for-the-authenticated-app
  if (parsedRepositoryNames) {
    const response = await request("GET /repos/{owner}/{repo}/installation", {
      owner: parsedOwner,
      repo: parsedRepositoryNames.split(",")[0],
      headers: {
        authorization: `bearer ${appAuthentication.token}`,
      },
    });

    // get token for given repositories
    authentication = await auth({
      type: "installation",
      installationId: response.data.id,
      repositoryNames: parsedRepositoryNames.split(","),
    });
  } else {
    // otherwise get the installation for the owner which can either be an organization or a user account
    // https://docs.github.com/en/rest/apps/apps?apiVersion=2022-11-28#get-a-repository-installation-for-the-authenticated-app
    const response = await request("GET /orgs/{org}/installation", {
      org: parsedOwner,
      headers: {
        authorization: `bearer ${appAuthentication.token}`,
      },
    }).catch((error) => {
      if (error.status !== 404) throw error;

      // https://docs.github.com/en/rest/apps/apps?apiVersion=2022-11-28#get-a-user-installation-for-the-authenticated-app
      return request("GET /users/{username}/installation", {
        username: parsedOwner,
        headers: {
          authorization: `bearer ${appAuthentication.token}`,
        },
      });
    });

    // get token for for all repositories of the given installation
    authentication = await auth({
      type: "installation",
      installationId: response.data.id,
    });
  }

  core.setOutput("token", authentication.token);
  // Register the token with the runner as a secret to ensure it is masked in logs
  core.setSecret(authentication.token);
  // Make token accessible to post function (so we can invalidate it)
  core.saveState("token", authentication.token);
}
