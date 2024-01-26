import { MockAgent, setGlobalDispatcher } from "undici";

// state variables are set as environment variables with the prefix STATE_
// https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions#sending-values-to-the-pre-and-post-actions
process.env.STATE_token = "secret123";

// inputs are set as environment variables with the prefix INPUT_
// https://docs.github.com/en/actions/creating-actions/metadata-syntax-for-github-actions#example-specifying-inputs
process.env["INPUT_GITHUB-API-URL"] = "https://api.github.com";

// 1 hour in the future, not expired
process.env.STATE_expiresAt = new Date(Date.now() + 1000 * 60 * 60).toISOString();

const mockAgent = new MockAgent();

setGlobalDispatcher(mockAgent);

// Provide the base url to the request
const mockPool = mockAgent.get("https://api.github.com");

// intercept the request
mockPool
  .intercept({
    path: "/installation/token",
    method: "DELETE",
    headers: {
      authorization: "token secret123",
    },
  })
  .reply(204);

await import("../post.js");
