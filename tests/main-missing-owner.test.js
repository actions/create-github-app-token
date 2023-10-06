process.env.GITHUB_REPOSITORY = "actions/create-github-app-token";
delete process.env.GITHUB_REPOSITORY_OWNER;

// Verify `main` exits with an error when `GITHUB_REPOSITORY_OWNER` is missing.
(async () => {
  try {
    await import("../main.js");
  } catch (error) {
    console.error(error.message);
  }
})();
