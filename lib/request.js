import core from "@actions/core";
import { request } from "@octokit/request";

// Get the GitHub API URL from the action input and remove any trailing slash
const baseUrl = core.getInput("github-api-url").replace(/\/$/, "");

// Configure the default settings for GitHub API requests
export default request.defaults({
  headers: { "user-agent": "actions/create-github-app-token" },
  baseUrl,
});
