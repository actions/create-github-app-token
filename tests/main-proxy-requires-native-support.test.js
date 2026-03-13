process.env.GITHUB_REPOSITORY = "actions/create-github-app-token";
process.env.GITHUB_REPOSITORY_OWNER = "actions";
process.env.HTTPS_PROXY = "http://127.0.0.1:3128";

const originalConsoleError = console.error;
console.error = (...args) => {
  originalConsoleError(
    ...args.map((arg) => (arg instanceof Error ? arg.message : arg)),
  );
};

await import("../main.js");
await new Promise((resolve) => setImmediate(resolve));
process.exitCode = 0;
