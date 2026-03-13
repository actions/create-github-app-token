process.env["INPUT_GITHUB-API-URL"] = "https://api.github.com";
process.env.HTTPS_PROXY = "http://127.0.0.1:3128";

try {
  await import("../post.js");
} catch (error) {
  console.error(error.message);
}
