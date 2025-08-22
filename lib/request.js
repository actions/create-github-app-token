import core from "@actions/core";
import { request } from "@octokit/request";

/* c8 ignore start -- env knob setup */
// Encourage Node to honor standard *_PROXY vars for core HTTP(S) agents.
if (process.env.NODE_USE_ENV_PROXY == null) {
  process.env.NODE_USE_ENV_PROXY = "1";
}
/* c8 ignore stop */

// Get the GitHub API URL from the action input and remove any trailing slash
const baseUrl = core.getInput("github-api-url").replace(/\/$/, "");

// Configure the default settings for GitHub API requests
export default request.defaults({
  headers: { "user-agent": "actions/create-github-app-token" },
  baseUrl,
});
