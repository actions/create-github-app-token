import core from "@actions/core";
import { request } from "@octokit/request";

// Get the GitHub API URL from the action input and remove any trailing slash
const baseUrl = core.getInput("github-api-url").replace(/\/$/, "");

const proxyEnvironmentKeys = [
  "https_proxy",
  "HTTPS_PROXY",
  "http_proxy",
  "HTTP_PROXY",
];

const useEnvProxyPattern = /(^|\s)--use[-_]env[-_]proxy(?=\s|$)/;

function proxyEnvironmentConfigured() {
  return proxyEnvironmentKeys.some((key) => process.env[key]);
}

function nativeProxySupportEnabled() {
  return (
    process.env.NODE_USE_ENV_PROXY === "1" ||
    process.execArgv.some((arg) => useEnvProxyPattern.test(arg)) ||
    useEnvProxyPattern.test(process.env.NODE_OPTIONS || "")
  );
}

export function ensureNativeProxySupport() {
  if (!proxyEnvironmentConfigured() || nativeProxySupportEnabled()) {
    return;
  }

  throw new Error(
    "HTTP_PROXY or HTTPS_PROXY is set, but Node.js native proxy support is not enabled. Set NODE_USE_ENV_PROXY=1 or NODE_OPTIONS=--use-env-proxy for this action step.",
  );
}

// Configure the default settings for GitHub API requests
export default request.defaults({
  headers: { "user-agent": "actions/create-github-app-token" },
  baseUrl,
});
