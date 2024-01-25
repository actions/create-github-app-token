// @ts-check

/**
 * @param {import("@actions/core")} core
 * @param {import("@octokit/request").request} request
 */
export async function post(core, request) {
  const skipTokenRevoke = Boolean(
    core.getInput("skip-token-revoke") || core.getInput("skip_token_revoke")
  );

  if (skipTokenRevoke) {
    core.info("Token revocation was skipped");
    return;
  }

  const token = core.getState("token");

  if (!token) {
    core.info("Token is not set");
    return;
  }

  const expiresAt = core.getState("expiresAt");
  if (expiresAt && tokenExpiresIn(expiresAt) < 0) {
    core.info("Token expired, skipping token revocation");
    return;
  }

  try {
    await request("DELETE /installation/token", {
      headers: {
        authorization: `token ${token}`,
      },
    });
    core.info("Token revoked");
  } catch (error) {
    core.warning(
      `Token revocation failed: ${error.message}`)
  }
}

/**
 * @param {string} expiresAt
 */
function tokenExpiresIn(expiresAt) {
  const now = new Date();
  const expiresAtDate = new Date(expiresAt);

  return Math.round((expiresAtDate.getTime() - now.getTime()) / 1000);
}
