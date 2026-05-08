import { install, MockAgent, setGlobalDispatcher } from "undici";

// Ensure MockAgent intercepts requests made through global fetch.
install();

export function createMockAgent(options) {
  const mockAgent = new MockAgent(options);
  mockAgent.disableNetConnect();
  setGlobalDispatcher(mockAgent);

  return mockAgent;
}
