// @ts-check

import { spawn } from "node:child_process";

/**
 * Wraps a function to automatically enable Node.js proxy support when proxy
 * environment variables are detected. If proxy env vars are set but
 * `NODE_USE_ENV_PROXY` is not `"1"`, spawns a child process with
 * `NODE_USE_ENV_PROXY=1` to enable native proxy support.
 *
 * @param {() => Promise<void>} run
 * @returns {Promise<void>}
 *
 * @see https://github.com/nodejs/node/blob/4612c793cb9007a91cb3fd82afe518440473826e/lib/internal/process/pre_execution.js#L168-L187
 */
export async function runWithProxy(run) {
  const httpProxyEnvVars = [
    "https_proxy",
    "HTTPS_PROXY",
    "http_proxy",
    "HTTP_PROXY",
  ];
  const nodeHasProxySupportEnabled = process.env.NODE_USE_ENV_PROXY === "1";
  const shouldUseProxy = httpProxyEnvVars.some((v) => process.env[v]);

  if (!nodeHasProxySupportEnabled && shouldUseProxy) {
    return new Promise((resolve, reject) => {
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

  return run();
}
