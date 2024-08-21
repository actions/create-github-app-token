import pRetry from "p-retry";
import { KMSClient, SignCommand } from "@aws-sdk/client-kms";
// @ts-check

/**
 * @param {string} appId
 * @param {string} kmsKeyId
 * @param {string} owner
 * @param {string} repositories
 * @param {import("@actions/core")} core
 * @param {import("@octokit/request").request} request
 * @param {boolean} skipTokenRevoke
 */
export async function main(
  appId,
  kmsKeyId,
  owner,
  repositories,
  core,
  request,
  skipTokenRevoke
) {
  let parsedOwner = "";
  let parsedRepositoryNames = "";

  // If neither owner nor repositories are set, default to current repository
  if (!owner && !repositories) {
    [parsedOwner, parsedRepositoryNames] = String(
      process.env.GITHUB_REPOSITORY
    ).split("/");

    core.info(
      `owner and repositories not set, creating token for the current repository ("${parsedRepositoryNames}")`
    );
  }

  // If only an owner is set, default to all repositories from that owner
  if (owner && !repositories) {
    parsedOwner = owner;

    core.info(
      `repositories not set, creating token for all repositories for given owner "${owner}"`
    );
  }

  // If repositories are set, but no owner, default to `GITHUB_REPOSITORY_OWNER`
  if (!owner && repositories) {
    parsedOwner = String(process.env.GITHUB_REPOSITORY_OWNER);
    parsedRepositoryNames = repositories;

    core.info(
      `owner not set, creating owner for given repositories "${repositories}" in current owner ("${parsedOwner}")`
    );
  }

  // If both owner and repositories are set, use those values
  if (owner && repositories) {
    parsedOwner = owner;
    parsedRepositoryNames = repositories;

    core.info(
      `owner and repositories set, creating token for repositories "${repositories}" owned by "${owner}"`
    );
  }
 
  const jwt = await createJWT({ appId: appId, kmsKeyId: kmsKeyId} )

  let authentication, installationId, appSlug;
  // If at least one repository is set, get installation ID from that repository

  if (parsedRepositoryNames) {
    ({ authentication, installationId, appSlug } = await pRetry(() => getTokenFromRepository(request, jwt, parsedOwner, parsedRepositoryNames), {
      onFailedAttempt: (error) => {
        core.info(
          `Failed to create token for "${parsedRepositoryNames}" (attempt ${error.attemptNumber}): ${error.message}`
        );
      },
      retries: 3,
    }));
  } else {
    // Otherwise get the installation for the owner, which can either be an organization or a user account
    ({ authentication, installationId, appSlug } = await pRetry(() => getTokenFromOwner(request, jwt, parsedOwner), {
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

async function getTokenFromOwner(request, jwt, parsedOwner) {
  // https://docs.github.com/en/rest/apps/apps?apiVersion=2022-11-28#get-an-organization-installation-for-the-authenticated-app
  const installationResponse = await request("GET /orgs/{org}/installation", {
    org: parsedOwner,
    headers: {
      authorization: `bearer ${jwt}`
    },
  }).catch((error) => {
    /* c8 ignore next */
    if (error.status !== 404) throw error;

    // https://docs.github.com/rest/apps/apps?apiVersion=2022-11-28#get-a-user-installation-for-the-authenticated-app
    return request("GET /users/{username}/installation", {
      username: parsedOwner,
      headers: {
        authorization: `bearer ${jwt}`
      },
    });
  });

  const accessTokenResponse = await request(`POST /app/installations/${installationResponse.data.id}/access_tokens`, {
    headers: {
      authorization: `bearer ${jwt}`
    },
    installationId: installationResponse.data.id
  }).catch ((error)=> {
    core.info(`Error obtaining the installation access token: ${error.message}`);
    throw error;
  });

  const authentication = accessTokenResponse.data
  const installationId = installationResponse.data.id;
  const appSlug = installationResponse.data['app_slug'];

  return { authentication, installationId, appSlug };
}

async function getTokenFromRepository(request, jwt, parsedOwner, parsedRepositoryNames) {
  // https://docs.github.com/rest/apps/apps?apiVersion=2022-11-28#get-a-repository-installation-for-the-authenticated-app
  const installationResponse = await request("GET /repos/{owner}/{repo}/installation", {
    owner: parsedOwner,
    repo: parsedRepositoryNames.split(",")[0],
    headers: {
      authorization: `bearer ${jwt}`
    },
  });

  // Get token for given repositories 
  const accessTokenResponse = await request(`POST /app/installations/${installationResponse.data.id}/access_tokens`, {
    headers: {
      authorization: `bearer ${jwt}`
    },
    installationId: installationResponse.data.id,
    repositories: parsedRepositoryNames.split(",")
  }).catch ((error)=> {
    core.info(`Error obtaining the installation access token: ${error.message}`);
    throw error;
  });

  const authentication = accessTokenResponse.data
  const installationId = installationResponse.data.id;
  const appSlug = installationResponse.data['app_slug'];

  return { authentication, installationId, appSlug };
}

async function createJWT({ appId, expirationTime = 600, httpRequestHandler = undefined, kmsKeyId }) {
  const now = Math.floor(Date.now() / 1000);
  const iat = now - 60; // Issued 60 seconds in the past
  const exp = now + expirationTime; // Expires expirationTime seconds in the future

  const header = {
      typ: 'JWT',
      alg: 'RS256',
  };

  const payload = {
      iat,
      exp,
      iss: appId,
  };

  // Base64 url encode the header and the payload
  const headerBase64 = Buffer.from(JSON.stringify(header)).toString('base64').replaceAll('=', '').replaceAll('+', '-').replaceAll('/', '_')
  const payloadBase64 = Buffer.from(JSON.stringify(payload)).toString('base64').replaceAll('=', '').replaceAll('+', '-').replaceAll('/', '_')

  const headerPayload = `${headerBase64}.${payloadBase64}`;

  const kmsClient = new KMSClient({
      requestHandler: httpRequestHandler,
  });

  const signInput = {
      KeyId: kmsKeyId,
      Message: headerPayload,
      MessageType: "RAW",
      SigningAlgorithm: "RSASSA_PKCS1_V1_5_SHA_256",
  };

  try {
      const signCommand = new SignCommand(signInput);
      const signatureResponse = await kmsClient.send(signCommand);
      const signatureBase64 = Buffer.from(signatureResponse.Signature).toString('base64').replaceAll('=', '').replaceAll('+', '-').replaceAll('/', '_');
      const jwt = `${headerPayload}.${signatureBase64}`;
      return jwt;
  } catch (error) {
      console.error("Error signing JWT:", error.message);
      return error;
  }
}