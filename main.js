// @ts-check

import core from "@actions/core";
import { createAppAuth } from "@octokit/auth-app";

import { getPermissionsFromInputs } from "./lib/get-permissions-from-inputs.js";
import { main } from "./lib/main.js";
import request from "./lib/request.js";

if (!process.env.GITHUB_REPOSITORY) {
  throw new Error("GITHUB_REPOSITORY missing, must be set to '<owner>/<repo>'");
}

if (!process.env.GITHUB_REPOSITORY_OWNER) {
  throw new Error("GITHUB_REPOSITORY_OWNER missing, must be set to '<owner>'");
}

async function run() {
  // spawn a child process if proxy is set
  const httpProxyEnvVars = [
    "https_proxy",
    "HTTPS_PROXY",
    "http_proxy",
    "HTTP_PROXY",
  ];
  const nodeHasProxySupportEnabled = process.env.NODE_USE_ENV_PROXY === "1";
  const shouldUseProxy = httpProxyEnvVars.some((v) => process.env[v]);

  // There is no other way to enable proxy support in Node.js as of 2025-09-19
  // https://github.com/nodejs/node/blob/4612c793cb9007a91cb3fd82afe518440473826e/lib/internal/process/pre_execution.js#L168-L187
  if (!nodeHasProxySupportEnabled && shouldUseProxy) {
    return new Promise(async (resolve, reject) => {
      const { spawn } = await import("node:child_process");
      // spawn itself with NODE_USE_ENV_PROXY=1
      const child = spawn(process.execPath, process.argv.slice(1), {
        env: { ...process.env, NODE_USE_ENV_PROXY: "1" },
        stdio: "inherit",
      });
      child.on("exit", (code) => {
        process.exitCode = code;
        if (code !== 0) {
          reject(new Error(`Child process exited with code ${code}`));
        } else {
          resolve();
        }
      });
    });
  }

  const appId = core.getInput("app-id");
  const privateKey = core.getInput("private-key");
  const owner = core.getInput("owner");
  const repositories = core
    .getInput("repositories")
    .split(/[\n,]+/)
    .map((s) => s.trim())
    .filter((x) => x !== "");

  const skipTokenRevoke = core.getBooleanInput("skip-token-revoke");

  const permissions = getPermissionsFromInputs(process.env);

  // Export promise for testing
  return main(
    appId,
    privateKey,
    owner,
    repositories,
    permissions,
    core,
    createAppAuth,
    request,
    skipTokenRevoke,
  ).catch((error) => {
    /* c8 ignore next 3 */
    console.error(error);
    core.setFailed(error.message);
  });
}

export default run();
