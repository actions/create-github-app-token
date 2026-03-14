import * as core from "@actions/core";
import { request } from "@octokit/request";

// Get the GitHub API URL from the action input and remove any trailing slash
const baseUrl = core.getInput("github-api-url").replace(/\/$/, "");

const proxyEnvironmentKeys = [
  "https_proxy",
  "HTTPS_PROXY",
  "http_proxy",
  "HTTP_PROXY",
];

function proxyEnvironmentConfigured() {
  return proxyEnvironmentKeys.some((key) => process.env[key]);
}

function nativeProxySupportEnabled() {
  return process.env.NODE_USE_ENV_PROXY === "1";
}

export function ensureNativeProxySupport() {
  if (!proxyEnvironmentConfigured() || nativeProxySupportEnabled()) {
    return;
  }

  throw new Error(
    "A proxy environment variable is set, but Node.js native proxy support is not enabled. Set NODE_USE_ENV_PROXY=1 for this action step.",
  );
}

// Configure the default settings for GitHub API requests
export default request.defaults({
  headers: { "user-agent": "actions/create-github-app-token" },
  baseUrl,
});
