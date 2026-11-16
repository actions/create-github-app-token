// @ts-check

/**
 * Creates an auth strategy compatible with `@octokit/auth-app` that authenticates
 * as a GitHub App using a GitHub Actions OIDC token instead of a private key.
 *
 * @param {string} clientId
 * @param {Pick<import("@actions/core"), "getIDToken">} core
 * @param {import("@octokit/request").request} request
 */
export async function createOidcAuth(clientId, core, request) {
  const audience = `${process.env.GITHUB_SERVER_URL || "https://github.com"}/login/oauth`;
  const token = await core.getIDToken(audience);

  /**
   * @param {{ installationId: number, repositoryNames?: string[], permissions?: Record<string, string> }} options
   */
  const auth = async ({ installationId, repositoryNames, permissions }) => {
    const { data } = await request(
      "POST /app/installations/{installation_id}/access_tokens{?client_id}",
      {
        installation_id: installationId,
        client_id: clientId,
        repositories: repositoryNames,
        permissions,
        headers: { authorization: `Bearer ${token}` },
      },
    );

    return { token: data.token, expiresAt: data.expires_at };
  };

  /**
   * @param {import("@octokit/request").request} hookRequest
   * @param {string} route
   * @param {Record<string, unknown>} [parameters]
   */
  auth.hook = (hookRequest, route, parameters) => {
    const endpoint = hookRequest.endpoint(route, parameters);
    const url = new URL(endpoint.url);
    url.searchParams.set("client_id", clientId);
    endpoint.url = url.toString();
    endpoint.headers.authorization = `Bearer ${token}`;
    return hookRequest(endpoint);
  };

  return auth;
}
