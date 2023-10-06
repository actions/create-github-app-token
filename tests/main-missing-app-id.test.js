process.env.GITHUB_REPOSITORY_OWNER = "actions";
process.env.GITHUB_REPOSITORY = "actions/create-github-app-token";

// Verify `main` exits with an error when neither the `app-id` nor `app_id` input is set.
try {
  await import("../main.js");
} catch (error) {
  console.error(error.message);
}
