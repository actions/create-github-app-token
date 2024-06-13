import core from "@actions/core";
import { request } from "@octokit/request";
const baseUrl = core.getInput("github-api-url").replace(/\/$/, "");

export default request.defaults({
  headers: {
    "user-agent": "actions/create-github-app-token",
  },
  baseUrl,
});
