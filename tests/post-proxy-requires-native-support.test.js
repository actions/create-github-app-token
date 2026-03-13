process.env["INPUT_GITHUB-API-URL"] = "https://api.github.com";
process.env.HTTPS_PROXY = "http://127.0.0.1:3128";

const originalConsoleError = console.error;
console.error = (...args) => {
  originalConsoleError(
    ...args.map((arg) => (arg instanceof Error ? arg.message : arg)),
  );
};

await import("../post.js");
await new Promise((resolve) => setImmediate(resolve));
process.exitCode = 0;
