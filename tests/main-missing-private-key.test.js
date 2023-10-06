process.env.GITHUB_REPOSITORY_OWNER = "actions";
process.env.GITHUB_REPOSITORY = "actions/create-github-app-token";
process.env["INPUT_APP-ID"] = "123456";

// Verify `main` exits with an error when neither the `private-key` nor `private_key` input is set.
try {
  await import("../main.js");
} catch (error) {
  console.error(error.message);
}
