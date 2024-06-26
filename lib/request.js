import core from "@actions/core";
import { request } from "@octokit/request";
import { fetch as undiciFetch } from "undici";

const baseUrl = core.getInput("github-api-url").replace(/\/$/, "");

export default request.defaults({
  headers: {
    "user-agent": "actions/create-github-app-token",
  },
  baseUrl,
  // Use undici for the fetch implementation because we rely on its built-in proxy support added in v6.14/15.
  // Node.js v20 uses an older undici version, and the GitHub Actions runner doesn't support node22 yet.
  request: {
    fetch: undiciFetch,
  },
});
