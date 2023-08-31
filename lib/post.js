// @ts-check

/**
 * @param {import("@actions/core")} core
 * @param {import("@octokit/request").request} request
 */
export async function post(core, request) {
  const token = core.getState("token");

  if (!token) {
    core.info("Token is not set");
    return;
  }

  await request("DELETE /installation/token", {
    headers: {
      authorization: `token ${token}`,
    },
  });

  core.info("Token revoked");
}
