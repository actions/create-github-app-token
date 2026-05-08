import { fetch as undiciFetch, MockAgent, setGlobalDispatcher } from "undici";

export function createMockAgent(options) {
  // Use npm Undici's fetch so MockAgent intercepts requests on Node 24.
  globalThis.fetch = undiciFetch;

  const mockAgent = new MockAgent(options);
  setGlobalDispatcher(mockAgent);

  return mockAgent;
}
