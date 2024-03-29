delete process.env.GITHUB_REPOSITORY;

// Verify `main` exits with an error when `GITHUB_REPOSITORY` is missing.
try {
  await import("../main.js");
} catch (error) {
  console.error(error.message);
}
