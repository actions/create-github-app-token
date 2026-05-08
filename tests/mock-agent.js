import { install, MockAgent, setGlobalDispatcher } from "undici";

// Keep fetch globals paired with the npm Undici instance that provides MockAgent.
install();

export function createMockAgent(options) {
  const mockAgent = new MockAgent(options);
  mockAgent.disableNetConnect();
  setGlobalDispatcher(mockAgent);

  return mockAgent;
}
