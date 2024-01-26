import { request } from "@octokit/request";

export default request.defaults({
  headers: {
    "user-agent": "actions/create-github-app-token",
  },
});
