process.env.GITHUB_REPOSITORY_OWNER = "lepadatu-org";
process.env.GITHUB_REPOSITORY = "lepadatu-org/create-github-app-token-aws";
process.env["INPUT_APP-ID"] = "123456";

// Verify `main` exits with an error when neither the `kms-key-id` nor `kms_key_id` input is set.
try {
  await import("../main.js");
} catch (error) {
  console.error(error.message);
}
