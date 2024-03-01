import core from "@actions/core";
import { request } from "@octokit/request";
import { ProxyAgent, fetch as undiciFetch } from "undici";

const baseUrl = core.getInput("github-api-url").replace(/\/$/, "");

// https://docs.github.com/actions/hosting-your-own-runners/managing-self-hosted-runners/using-a-proxy-server-with-self-hosted-runners
const proxyUrl =
  process.env.https_proxy ||
  process.env.HTTPS_PROXY ||
  process.env.http_proxy ||
  process.env.HTTP_PROXY;

/* c8 ignore start */
// Native support for proxies in Undici is under consideration: https://github.com/nodejs/undici/issues/1650
// Until then, we need to use a custom fetch function to add proxy support.
const proxyFetch = (url, options) => {
  const urlHost = new URL(url).hostname;
  const noProxy = (process.env.no_proxy || process.env.NO_PROXY || "").split(
    ","
  );

  if (!noProxy.includes(urlHost)) {
    options = {
      ...options,
      dispatcher: new ProxyAgent(String(proxyUrl)),
    };
  }

  return undiciFetch(url, options);
};
/* c8 ignore stop */

export default request.defaults({
  headers: {
    "user-agent": "actions/create-github-app-token",
  },
  baseUrl,
  /* c8 ignore next */
  request: proxyUrl ? { fetch: proxyFetch } : {},
});
