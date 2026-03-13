process.env.GITHUB_REPOSITORY = "actions/create-github-app-token";
process.env.GITHUB_REPOSITORY_OWNER = "actions";
process.env.HTTPS_PROXY = "http://127.0.0.1:3128";

try {
  await import("../main.js");
} catch (error) {
  console.error(error.message);
}
