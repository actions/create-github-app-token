import core from "@actions/core";
import { request } from "@octokit/request";
import { EnvHttpProxyAgent, fetch as undiciFetch } from "undici";

const baseUrl = core.getInput("github-api-url").replace(/\/$/, "");

const envHttpProxyAgent = new EnvHttpProxyAgent();

export default request.defaults({
  headers: {
    "user-agent": "actions/create-github-app-token",
  },
  baseUrl,
  request: {
    fetch: undiciFetch,
    dispatcher: envHttpProxyAgent
  },
});
