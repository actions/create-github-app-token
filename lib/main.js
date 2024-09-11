import pRetry from "p-retry";
// @ts-check

/**
 * @param {string} appId
 * @param {string} privateKey
 * @param {string} owner
 * @param {string[]} repositories
 * @param {import("@actions/core")} core
 * @param {import("@octokit/auth-app").createAppAuth} createAppAuth
 * @param {import("@octokit/request").request} request
 * @param {boolean} skipTokenRevoke
 */
export async function main(
  appId,
  privateKey,
  owner,
  repositories,
  core,
  createAppAuth,
  request,
  skipTokenRevoke
) {
  let parsedOwner = "";
  let parsedRepositoryNames = [];

  // If neither owner nor repositories are set, default to current repository
  if (!owner && repositories.length === 0) {
    const [owner, repo] = String(
      process.env.GITHUB_REPOSITORY
    ).split("/");
    parsedOwner = owner;
    parsedRepositoryNames = [repo];

    core.info(
      `owner and repositories not set, creating token for the current repository ("${repo}")`
    );
  }

  // If only an owner is set, default to all repositories from that owner
  if (owner && repositories.length === 0) {
    parsedOwner = owner;

    core.info(
      `repositories not set, creating token for all repositories for given owner "${owner}"`
    );
  }

  // If repositories are set, but no owner, default to `GITHUB_REPOSITORY_OWNER`
  if (!owner && repositories.length > 0) {
    parsedOwner = String(process.env.GITHUB_REPOSITORY_OWNER);
    parsedRepositoryNames = repositories;

    core.info(
      `owner not set, creating owner for given repositories "${repositories.join(',')}" in current owner ("${parsedOwner}")`
    );
  }

  // If both owner and repositories are set, use those values
  if (owner && repositories.length > 0) {
    parsedOwner = owner;
    parsedRepositoryNames = repositories;

    core.info(
      `owner and repositories set, creating token for repositories "${repositories.join(',')}" owned by "${owner}"`
    );
  }

  const auth = createAppAuth({
    appId,
    privateKey,
    request,
  });

  let authentication, installationId, appSlug;
  // If at least one repository is set, get installation ID from that repository

  if (parsedRepositoryNames.length > 0) {
    ({ authentication, installationId, appSlug } = await pRetry(() => getTokenFromRepository(request, auth, parsedOwner, parsedRepositoryNames), {
      onFailedAttempt: (error) => {
        core.info(
          `Failed to create token for "${parsedRepositoryNames.join(',')}" (attempt ${error.attemptNumber}): ${error.message}`
        );
      },
      retries: 3,
    }));
  } else {
    // Otherwise get the installation for the owner, which can either be an organization or a user account
    ({ authentication, installationId, appSlug } = await pRetry(() => getTokenFromOwner(request, auth, parsedOwner), {
      onFailedAttempt: (error) => {
        core.info(
          `Failed to create token for "${parsedOwner}" (attempt ${error.attemptNumber}): ${error.message}`
        );
      },
      retries: 3,
    }));
  }

  // Register the token with the runner as a secret to ensure it is masked in logs
  core.setSecret(authentication.token);

  core.setOutput("token", authentication.token);
  core.setOutput("installation-id", installationId);
  core.setOutput("app-slug", appSlug);

  // Make token accessible to post function (so we can invalidate it)
  if (!skipTokenRevoke) {
    core.saveState("token", authentication.token);
    core.saveState("expiresAt", authentication.expiresAt);
  }
}

async function getTokenFromOwner(request, auth, parsedOwner) {
  // https://docs.github.com/en/rest/apps/apps?apiVersion=2022-11-28#get-an-organization-installation-for-the-authenticated-app
  const response = await request("GET /orgs/{org}/installation", {
    org: parsedOwner,
    request: {
      hook: auth.hook,
    },
  }).catch((error) => {
    /* c8 ignore next */
    if (error.status !== 404) throw error;

    // https://docs.github.com/rest/apps/apps?apiVersion=2022-11-28#get-a-user-installation-for-the-authenticated-app
    return request("GET /users/{username}/installation", {
      username: parsedOwner,
      request: {
        hook: auth.hook,
      },
    });
  });

  // Get token for for all repositories of the given installation
  const authentication = await auth({
    type: "installation",
    installationId: response.data.id,
  });

  const installationId = response.data.id;
  const appSlug = response.data['app_slug'];

  return { authentication, installationId, appSlug };
}

async function getTokenFromRepository(request, auth, parsedOwner, parsedRepositoryNames) {
  // https://docs.github.com/rest/apps/apps?apiVersion=2022-11-28#get-a-repository-installation-for-the-authenticated-app
  const response = await request("GET /repos/{owner}/{repo}/installation", {
    owner: parsedOwner,
    repo: parsedRepositoryNames[0],
    request: {
      hook: auth.hook,
    },
  });

  // Get token for given repositories
  const authentication = await auth({
    type: "installation",
    installationId: response.data.id,
    repositoryNames: parsedRepositoryNames,
  });

  const installationId = response.data.id;
  const appSlug = response.data['app_slug'];

  return { authentication, installationId, appSlug };
}
