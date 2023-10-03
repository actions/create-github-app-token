// Verify `main` exits with an error when `GITHUB_REPOSITORY` is missing.
// @ts-check

delete process.env.GITHUB_REPOSITORY;

(async () => {
  try {
    await import("../main.js");
  } catch (error) {
    console.error(error.message);
  }
})();
