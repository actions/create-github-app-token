import core from "@actions/core";
import { request } from "@octokit/request";
import { EnvHttpProxyAgent, fetch as undiciFetch } from "undici";

// Get the GitHub API URL from the action input and remove any trailing slash
const baseUrl = core.getInput("github-api-url").replace(/\/$/, "");

const proxyConfigured =
  process.env.https_proxy ||
  process.env.HTTPS_PROXY ||
  process.env.http_proxy ||
  process.env.HTTP_PROXY;

const proxyAgent = proxyConfigured ? new EnvHttpProxyAgent() : undefined;

// Configure the default settings for GitHub API requests
export default request.defaults({
  headers: { "user-agent": "actions/create-github-app-token" },
  baseUrl,
  request: proxyConfigured
    ? {
        fetch: (url, options) =>
          undiciFetch(url, {
            ...options,
            dispatcher: proxyAgent,
          }),
      }
    : {},
});
