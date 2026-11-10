export async function createOidcAuth(clientId, core, request) {
  if (!process.env.ACTIONS_ID_TOKEN_REQUEST_URL || !process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN) {
    throw new Error("OIDC authentication requires 'id-token: write' workflow permissions. Alternatively, provide 'private-key'.");
  }

  const audience = `${process.env.GITHUB_SERVER_URL || "https://github.com"}/login/oauth`;
  const token = await core.getIDToken(audience);

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