import { strict as assert } from 'node:assert';

import core from "@actions/core";
import { Agent, MockAgent, setGlobalDispatcher } from "undici";

process.env.STATE_token = "secret123";

// // https://undici.nodejs.org/#/docs/best-practices/writing-tests
// const agent = new Agent({
//   keepAliveTimeout: 10, // milliseconds
//   keepAliveMaxTimeout: 10 // milliseconds
// })

// setGlobalDispatcher(agent)

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

const outputs = []
console.log = (message) => outputs.push(message);
// core.info = (message) => outputs.push(message);

await import("../post.js");

assert.deepEqual(outputs, ["Token revoked"]);
