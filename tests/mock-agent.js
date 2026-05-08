import { fetch as undiciFetch, MockAgent, setGlobalDispatcher } from "undici";

// Keep npm Undici's fetch paired with npm Undici's MockAgent on Node 24.
globalThis.fetch = undiciFetch;

export function createMockAgent(options) {
  const mockAgent = new MockAgent(options);
  setGlobalDispatcher(mockAgent);

  return mockAgent;
}
