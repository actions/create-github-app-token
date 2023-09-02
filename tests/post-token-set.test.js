import { MockAgent, setGlobalDispatcher } from "undici";

// state variables are set as environment variables with the prefix STATE_
// https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions#sending-values-to-the-pre-and-post-actions
process.env.STATE_token = "secret123";

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
