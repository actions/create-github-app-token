// @ts-check

import core from "@actions/core";
import { fetch as undiciFetch, ProxyAgent } from "undici";

import { post } from "./lib/post.js";
import request from "./lib/request.js";

const baseUrl = core.getInput("github-api-url").replace(/\/$/, "");

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

post(
  core,
  request.defaults({
    baseUrl,
    request: proxyUrl ? { fetch: proxyFetch } : {},
  })
).catch((error) => {
  /* c8 ignore next 3 */
  console.error(error);
  core.setFailed(error.message);
});
