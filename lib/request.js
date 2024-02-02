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

const proxyFetch = (url, options) => {
  return undiciFetch(url, {
    ...options,
    dispatcher: new ProxyAgent(String(proxyUrl)),
  });
};

export default request.defaults({
  headers: {
    "user-agent": "actions/create-github-app-token",
  },
  baseUrl,
  request: proxyUrl ? { fetch: proxyFetch } : {},
});
