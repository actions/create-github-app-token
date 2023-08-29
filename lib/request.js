import { request } from "@octokit/request";

export default request.defaults({
  baseUrl: process.env["GITHUB_API_URL"],
  headers: {
    "user-agent": "actions/create-github-app-token",
  },
});
