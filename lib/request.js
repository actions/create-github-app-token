import core from "@actions/core";
import { request } from "@octokit/request";
import { EnvHttpProxyAgent, setGlobalDispatcher } from "undici";

// Get the GitHub API URL from the action input and remove any trailing slash
const baseUrl = core.getInput("github-api-url").replace(/\/$/, "");

// Automatically detect/support proxy configuration from environment variables
// This may be the default global dispatcher in a future release of Node.js
// https://github.com/nodejs/node/issues/43187
const envHttpProxyAgent = new EnvHttpProxyAgent();
setGlobalDispatcher(envHttpProxyAgent);

// Configure the default settings for GitHub API requests
export default request.defaults({
  headers: { "user-agent": "actions/create-github-app-token" },
  baseUrl,
});
