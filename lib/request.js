import core from "@actions/core";
import { request } from "@octokit/request";
import { EnvHttpProxyAgent, setGlobalDispatcher } from "undici";

const baseUrl = core.getInput("github-api-url").replace(/\/$/, "");

const envHttpProxyAgent = new EnvHttpProxyAgent()
setGlobalDispatcher(envHttpProxyAgent)

export default request.defaults({
  headers: {
    "user-agent": "actions/create-github-app-token",
  },
  baseUrl,
});
