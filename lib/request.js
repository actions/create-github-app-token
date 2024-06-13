import core from "@actions/core";
import { request } from "@octokit/request";
import { fetch as undiciFetch } from "undici";

const baseUrl = core.getInput("github-api-url").replace(/\/$/, "");

export default request.defaults({
  headers: {
    "user-agent": "actions/create-github-app-token",
  },
  baseUrl,
  // Use undici as the fetch implementation because we rely on proxy support which is only available in node22 and later,
  // which the GitHub Actions runner doesn't support yet.
  request: {
    fetch: undiciFetch,
  },
});
