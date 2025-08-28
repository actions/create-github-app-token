import pRetry from "p-retry";
// @ts-check

/**
 * @param {string} appId
 * @param {string} privateKey
 * @param {string} enterpriseSlug
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
  enterpriseSlug,
  owner,
  repositories,
  permissions,
  core,
  createAppAuth,
  request,
  skipTokenRevoke,

) {
  // Validate mutual exclusivity of enterprise-slug with owner/repositories
  if (enterpriseSlug && (owner || repositories.length > 0)) {
    throw new Error("Cannot use 'enterprise-slug' input with 'owner' or 'repositories' inputs");
  }

  let parsedOwner = "";
  let parsedRepositoryNames = [];

  // Skip owner/repository parsing if enterprise is set
  if (!enterprise) {
    // If neither owner nor repositories are set, default to current repository
    if (!owner && repositories.length === 0) {
      const [owner, repo] = String(process.env.GITHUB_REPOSITORY).split("/");
      parsedOwner = owner;
      parsedRepositoryNames = [repo];

      core.info(
        `Inputs 'owner' and 'repositories' are not set. Creating token for this repository (${owner}/${repo}).`
      );
    }

    // If only an owner is set, default to all repositories from that owner
    if (owner && repositories.length === 0) {
      parsedOwner = owner;

      core.info(
        `Input 'repositories' is not set. Creating token for all repositories owned by ${owner}.`
      );
    }

    // If repositories are set, but no owner, default to `GITHUB_REPOSITORY_OWNER`
    if (!owner && repositories.length > 0) {
      parsedOwner = String(process.env.GITHUB_REPOSITORY_OWNER);
      parsedRepositoryNames = repositories;

      core.info(
        `No 'owner' input provided. Using default owner '${parsedOwner}' to create token for the following repositories:${repositories
          .map((repo) => `\n- ${parsedOwner}/${repo}`)
          .join("")}`
      );
    }

    // If both owner and repositories are set, use those values
    if (owner && repositories.length > 0) {
      parsedOwner = owner;
      parsedRepositoryNames = repositories;

      core.info(
        `Inputs 'owner' and 'repositories' are set. Creating token for the following repositories:
        ${repositories.map((repo) => `\n- ${parsedOwner}/${repo}`).join("")}`
      );
    }
  } else {
    core.info(`Creating enterprise installation token for enterprise "${enterprise}".`);
  }

  const auth = createAppAuth({
    appId,
    privateKey,
    request,
  });

  let authentication, installationId, appSlug;
  
  // If enterprise is set, get installation ID from the enterprise
  if (enterprise) {
    ({ authentication, installationId, appSlug } = await pRetry(
      () => getTokenFromEnterprise(request, auth, enterprise, permissions),
      {
        shouldRetry: (error) => error.status >= 500,
        onFailedAttempt: (error) => {
          core.info(
            `Failed to create token for enterprise "${enterprise}" (attempt ${error.attemptNumber}): ${error.message}`
          );
        },
        retries: 3,
      }
    ));
  } else if (parsedRepositoryNames.length > 0) {
    ({ authentication, installationId, appSlug } = await pRetry(
      () =>
        getTokenFromRepository(
          request,
          auth,
          parsedOwner,
          parsedRepositoryNames,
          permissions
        ),
      {
        shouldRetry: (error) => error.status >= 500,
        onFailedAttempt: (error) => {
          core.info(
            `Failed to create token for "${parsedRepositoryNames.join(
              ","
            )}" (attempt ${error.attemptNumber}): ${error.message}`
          );
        },
        retries: 3,
      }
    ));
  } else {
    // Otherwise get the installation for the owner, which can either be an organization or a user account
    ({ authentication, installationId, appSlug } = await pRetry(
      () => getTokenFromOwner(request, auth, parsedOwner, permissions),
      {
        onFailedAttempt: (error) => {
          core.info(
            `Failed to create token for "${parsedOwner}" (attempt ${error.attemptNumber}): ${error.message}`
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

async function getTokenFromOwner(request, auth, parsedOwner, permissions) {
  // https://docs.github.com/rest/apps/apps?apiVersion=2022-11-28#get-a-user-installation-for-the-authenticated-app
  // This endpoint works for both users and organizations
  const response = await request("GET /users/{username}/installation", {
    username: parsedOwner,
    request: {
      hook: auth.hook,
    },
  });

  // Get token for for all repositories of the given installation
  const authentication = await auth({
    type: "installation",
    installationId: response.data.id,
    permissions,
  });

  const installationId = response.data.id;
  const appSlug = response.data["app_slug"];

  return { authentication, installationId, appSlug };
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
  const authentication = await auth({
    type: "installation",
    installationId: response.data.id,
    repositoryNames: parsedRepositoryNames,
    permissions,
  });

  const installationId = response.data.id;
  const appSlug = response.data["app_slug"];

  return { authentication, installationId, appSlug };
}

async function getTokenFromEnterprise(request, auth, enterprise, permissions) {  
  // Get all installations and find the enterprise one
  // https://docs.github.com/rest/apps/apps#list-installations-for-the-authenticated-app
  // Note: Currently we do not have a way to get the installation for an enterprise directly,
  // so as a workaround we need to list all installations and filter for the enterprise one.
  const response = await request("GET /app/installations", {
    request: {
      hook: auth.hook,
    },
  });

  // Find the enterprise installation
  const enterpriseInstallation = response.data.find(
    installation => installation.target_type === "Enterprise" && 
    installation.account?.slug === enterprise
  );

  if (!enterpriseInstallation) {
    throw new Error(`No enterprise installation found matching the name ${enterprise}. Available installations: ${response.data.map(i => `${i.target_type}:${i.account?.login || 'N/A'}`).join(', ')}`);
  }

  // Get token for the enterprise installation
  const authentication = await auth({
    type: "installation",
    installationId: enterpriseInstallation.id,
    permissions,
  });

  const installationId = enterpriseInstallation.id;
  const appSlug = enterpriseInstallation["app_slug"];

  return { authentication, installationId, appSlug };
}
