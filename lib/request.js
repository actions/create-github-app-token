import core from "@actions/core";
import { request } from "@octokit/request";

/* c8 ignore start -- proxy setup depends on external runner env */
// Ensure env-based proxying for Node core agents unless explicitly disabled.
if (process.env.NODE_USE_ENV_PROXY == null) {
  process.env.NODE_USE_ENV_PROXY = "1";
}
// Attempt to configure undici global dispatcher (used by octokit under the hood)
// if a proxy environment variable is present. Failures are non-fatal.
const __proxyUrl =
  process.env.https_proxy ||
  process.env.HTTPS_PROXY ||
  process.env.http_proxy ||
  process.env.HTTP_PROXY;
if (__proxyUrl) {
  (async () => {
    try {
      const { setGlobalDispatcher, ProxyAgent } = await import("undici");
      setGlobalDispatcher(new ProxyAgent(__proxyUrl));
    } catch (e) {
      // eslint-disable-next-line no-console
      console.warn("Proxy setup failed:", e.message);
    }
  })();
}
/* c8 ignore stop */

// Get the GitHub API URL from the action input and remove any trailing slash
const baseUrl = core.getInput("github-api-url").replace(/\/$/, "");

// Configure the default settings for GitHub API requests
export default request.defaults({
  headers: { "user-agent": "actions/create-github-app-token" },
  baseUrl,
});
