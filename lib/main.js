import pRetry from "p-retry";
import isNetworkError from "is-network-error";
// @ts-check

/**
 * @param {string} clientId
 * @param {string} privateKey
 * @param {string} jwt
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
  clientId,
  privateKey,
  jwt,
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
    appId: clientId,
    ...resolveAppAuthStrategyOptions(privateKey, jwt),
    request,
  });

  const { authentication, installationId, appSlug } = await pRetry(
    () => getTokenFromTarget(request, auth, target, permissions),
    createTokenRetryOptions(core, getTokenRetryDescription(target))
  );

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

function resolveAppAuthStrategyOptions(privateKey, jwt) {
  if (!jwt) return { privateKey };

  // The caller signed the JWT themselves, so pass it on instead of signing one
  const expiresAt = decodeJwtExpiration(jwt);

  return { createJwt: async () => ({ jwt, expiresAt }) };
}

function decodeJwtExpiration(jwt) {
  let exp;

  // The signature is not checked here, GitHub verifies the token
  try {
    const [, payload] = jwt.split(".");
    ({ exp } = JSON.parse(Buffer.from(payload, "base64url").toString()));
  } catch {
    throw new Error("The 'jwt' input could not be decoded as a JSON Web Token.");
  }

  if (typeof exp !== "number") {
    throw new Error("The 'jwt' input has no numeric 'exp' claim.");
  }

  return new Date(exp * 1000).toISOString();
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

  const target = normalizeRepositoryTarget(owner, repositories);

  if (!owner) {
    core.info(
      `No 'owner' input provided. Using default owner '${target.owner}' to create token for the following repositories:${target.repositories
        .map((repo) => `\n- ${target.owner}/${repo}`)
        .join("")}`
    );
  } else {
    core.info(
      `Inputs 'owner' and 'repositories' are set. Creating token for the following repositories:${target.repositories
        .map((repo) => `\n- ${target.owner}/${repo}`)
        .join("")}`
    );
  }

  return {
    type: "repository",
    owner: target.owner,
    repositories: target.repositories,
  };
}

function normalizeRepositoryTarget(owner, repositories) {
  const parsedOwner = owner || String(process.env.GITHUB_REPOSITORY_OWNER);
  const parsedRepositories = repositories.map(parseRepositoryInput);

  const mismatchedRepository = parsedRepositories.find(
    (repository) =>
      repository.owner &&
      repository.owner.toLowerCase() !== parsedOwner.toLowerCase()
  );

  if (mismatchedRepository) {
    throw new Error(
      `Repository '${mismatchedRepository.input}' includes owner '${mismatchedRepository.owner}', which does not match the resolved owner '${parsedOwner}'.`
    );
  }

  return {
    owner: parsedOwner,
    repositories: parsedRepositories.map((repository) => repository.name),
  };
}

function parseRepositoryInput(input) {
  const parts = input.split("/");

  if (parts.length === 1 && parts[0]) {
    return { input, owner: "", name: parts[0] };
  }

  if (parts.length === 2 && parts[0] && parts[1]) {
    return { input, owner: parts[0], name: parts[1] };
  }

  throw new Error(
    `Invalid repository '${input}'. Expected 'repository' or 'owner/repository'.`
  );
}

function getTokenRetryDescription(target) {
  switch (target.type) {
    case "enterprise":
      return `enterprise "${target.enterprise}"`;
    case "repository":
      return `"${target.repositories
        .map((repository) => `${target.owner}/${repository}`)
        .join(",")}"`;
    case "owner":
      return `"${target.owner}"`;
    /* c8 ignore next 2 */
    default:
      throw new Error(`Unsupported installation target type: ${target.type}`);
  }
}

function getTokenFromTarget(request, auth, target, permissions) {
  switch (target.type) {
    case "enterprise":
      return getTokenFromEnterprise(request, auth, target.enterprise, permissions);
    case "repository":
      return getTokenFromRepository(
        request,
        auth,
        target.owner,
        target.repositories,
        permissions
      );
    case "owner":
      return getTokenFromOwner(request, auth, target.owner, permissions);
    /* c8 ignore next 2 */
    default:
      throw new Error(`Unsupported installation target type: ${target.type}`);
  }
}

function createTokenRetryOptions(core, targetDescription) {
  return {
    shouldRetry: ({ error }) => error.status >= 500 || isNetworkError(error),
    onFailedAttempt: (context) => {
      core.info(
        `Failed to create token for ${targetDescription} (attempt ${context.attemptNumber}): ${context.error.message}`
      );
    },
    retries: 3,
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
    if (error.status === 404) {
      throw new Error(
        `No enterprise installation found matching the enterprise slug "${enterprise}".`
      );
    }

    throw error;
  }

  // Get token for the enterprise installation
  return createInstallationAuthResult(auth, response.data, permissions);
}
