import { request, setGlobalDispatcher, Agent } from 'undici'

delete process.env.STATE_token

// https://undici.nodejs.org/#/docs/best-practices/writing-tests
const agent = new Agent({
  keepAliveTimeout: 10, // milliseconds
  keepAliveMaxTimeout: 10 // milliseconds
})

setGlobalDispatcher(agent)

await import('../post.js')
