import pRetry from "p-retry";
// @ts-check

/**
 * @param {string} appId
 * @param {string} privateKey
 * @param {string} enterprise
 * @param {string} owner
 * @param {string[]} repositories
 * @param {undefined | Record<string, string>} permissions
 * @param {import("@actions/core")} core
 * @param {import("@octokit/auth-app").createAppAuth} createAppAuth
 * @param {import("@octokit/request").request} request
 * @param {boolean} skipTokenRevoke
 */
export async function main(
  appId,
  privateKey,
  enterprise,
  owner,
  repositories,
  permissions,
  core,
  createAppAuth,
  request,
  skipTokenRevoke,
) {
  // Validate mutual exclusivity of enterprise with owner/repositories
  if (enterprise && (owner || repositories.length > 0)) {
    throw new Error("Cannot use 'enterprise' input with 'owner' or 'repositories' inputs");
  }

  const target = resolveInstallationTarget(enterprise, owner, repositories, core);

  const auth = createAppAuth({
    appId,
    privateKey,
    request,
  });

  let authentication, installationId, appSlug;

  if (target.type === "enterprise") {
    ({ authentication, installationId, appSlug } = await pRetry(
      () => getTokenFromEnterprise(request, auth, target.enterprise, permissions),
      {
        shouldRetry: ({ error }) => error.status >= 500,
        onFailedAttempt: (context) => {
          core.info(
            `Failed to create token for enterprise "${target.enterprise}" (attempt ${context.attemptNumber}): ${context.error.message}`
          );
        },
        retries: 3,
      }
    ));
  } else if (target.type === "repository") {
    ({ authentication, installationId, appSlug } = await pRetry(
      () =>
        getTokenFromRepository(
          request,
          auth,
          target.owner,
          target.repositories,
          permissions
        ),
      {
        shouldRetry: ({ error }) => error.status >= 500,
        onFailedAttempt: (context) => {
          core.info(
            `Failed to create token for "${target.repositories.join(
              ","
            )}" (attempt ${context.attemptNumber}): ${context.error.message}`
          );
        },
        retries: 3,
      }
    ));
  } else {
    // Otherwise get the installation for the owner, which can either be an organization or a user account
    ({ authentication, installationId, appSlug } = await pRetry(
      () => getTokenFromOwner(request, auth, target.owner, permissions),
      {
        onFailedAttempt: (context) => {
          core.info(
            `Failed to create token for "${target.owner}" (attempt ${context.attemptNumber}): ${context.error.message}`
          );
        },
        retries: 3,
      }
    ));
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

function resolveInstallationTarget(enterprise, owner, repositories, core) {
  if (enterprise) {
    core.info(`Creating enterprise installation token for enterprise "${enterprise}".`);
    return { type: "enterprise", enterprise };
  }

  if (!owner && repositories.length === 0) {
    const [defaultOwner, repo] = String(process.env.GITHUB_REPOSITORY).split("/");

    core.info(
      `Inputs 'owner' and 'repositories' are not set. Creating token for this repository (${defaultOwner}/${repo}).`
    );

    return {
      type: "repository",
      owner: defaultOwner,
      repositories: [repo],
    };
  }

  if (owner && repositories.length === 0) {
    core.info(
      `Input 'repositories' is not set. Creating token for all repositories owned by ${owner}.`
    );

    return { type: "owner", owner };
  }

  const parsedOwner = owner || String(process.env.GITHUB_REPOSITORY_OWNER);

  if (!owner) {
    core.info(
      `No 'owner' input provided. Using default owner '${parsedOwner}' to create token for the following repositories:${repositories
        .map((repo) => `\n- ${parsedOwner}/${repo}`)
        .join("")}`
    );
  } else {
    core.info(
      `Inputs 'owner' and 'repositories' are set. Creating token for the following repositories:
      ${repositories.map((repo) => `\n- ${parsedOwner}/${repo}`).join("")}`
    );
  }

  return {
    type: "repository",
    owner: parsedOwner,
    repositories,
  };
}

async function createInstallationAuthResult(
  auth,
  installation,
  permissions,
  options = {},
) {
  const authentication = await auth({
    type: "installation",
    installationId: installation.id,
    permissions,
    ...options,
  });

  return {
    authentication,
    installationId: installation.id,
    appSlug: installation["app_slug"],
  };
}

async function getTokenFromOwner(request, auth, parsedOwner, permissions) {
  // https://docs.github.com/rest/apps/apps?apiVersion=2022-11-28#get-a-user-installation-for-the-authenticated-app
  // This endpoint works for both users and organizations
  const response = await request("GET /users/{username}/installation", {
    username: parsedOwner,
    request: {
      hook: auth.hook,
    },
  });

  // Get token for all repositories of the given installation
  return createInstallationAuthResult(auth, response.data, permissions);
}

async function getTokenFromRepository(
  request,
  auth,
  parsedOwner,
  parsedRepositoryNames,
  permissions
) {
  // https://docs.github.com/rest/apps/apps?apiVersion=2022-11-28#get-a-repository-installation-for-the-authenticated-app
  const response = await request("GET /repos/{owner}/{repo}/installation", {
    owner: parsedOwner,
    repo: parsedRepositoryNames[0],
    request: {
      hook: auth.hook,
    },
  });

  // Get token for given repositories
  return createInstallationAuthResult(auth, response.data, permissions, {
    repositoryNames: parsedRepositoryNames,
  });
}

async function getTokenFromEnterprise(request, auth, enterprise, permissions) {
  let response;
  try {
    response = await request("GET /enterprises/{enterprise}/installation", {
      enterprise,
      request: {
        hook: auth.hook,
      },
    });
  } catch (error) {
    /* c8 ignore next 3 */
    if (error.status !== 404) {
      throw error;
    }

    throw new Error(
      `No enterprise installation found matching the name ${enterprise}.`
    );
  }

  // Get token for the enterprise installation
  return createInstallationAuthResult(auth, response.data, permissions);
}
