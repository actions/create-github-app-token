// Verify `main` overrides `request`’s default `baseUrl` when `GITHUB_API_URL` is set.
// @ts-check

import esmock from "esmock";

process.env.GITHUB_REPOSITORY = "actions/create-github-app-token";
process.env.GITHUB_API_URL = "https://github.acme-inc.com/api/v3";

// inputs are set as environment variables with the prefix INPUT_
// https://docs.github.com/en/actions/creating-actions/metadata-syntax-for-github-actions#example-specifying-inputs
process.env.INPUT_APP_ID = "123456";
process.env.INPUT_PRIVATE_KEY = `-----BEGIN RSA PRIVATE KEY-----
ABC/def/123==
-----END RSA PRIVATE KEY-----`;

await esmock("../main.js", {
  "../lib/main.js": {
    main: async (
      _appId,
      _privateKey,
      _repository,
      _core,
      _createAppAuth,
      request
    ) => {
      console.log(request.endpoint.DEFAULTS.baseUrl);
      console.log(request.endpoint.DEFAULTS.headers["user-agent"]);
    },
  },
});
