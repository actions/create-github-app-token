import { test } from "./main.js";

// Verify `main` validates the token after creation (happy path - succeeds on first attempt).
await test((mockPool) => {
  delete process.env.INPUT_OWNER;
  delete process.env.INPUT_REPOSITORIES;
});
