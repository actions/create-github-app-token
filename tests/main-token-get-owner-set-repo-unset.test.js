// Verify `main` creates a token when the `owner` input is set but the `repositories` input is not set.
// @ts-check
import { MockAgent, setGlobalDispatcher } from "undici";

// Set required environment variables and inputs
process.env.GITHUB_REPOSITORY_OWNER = "actions";
process.env.GITHUB_REPOSITORY = "actions/create-github-app-token";
// inputs are set as environment variables with the prefix INPUT_
// https://docs.github.com/en/actions/creating-actions/metadata-syntax-for-github-actions#example-specifying-inputs
process.env.INPUT_OWNER = process.env.GITHUB_REPOSITORY_OWNER;
delete process.env.INPUT_REPOSITORIES;
process.env.INPUT_APP_ID = "123456";
process.env.INPUT_PRIVATE_KEY = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA280nfuUM9w00Ib9E2rvZJ6Qu3Ua3IqR34ZlK53vn/Iobn2EL
Z9puc5Q/nFBU15NKwHyQNb+OG2hTCkjd1Xi9XPzEOH1r42YQmTGq8YCkUSkk6KZA
5dnhLwN9pFquT9fQgrf4r1D5GJj3rqvj8JDr1sBmunArqY5u4gziSrIohcjLIZV0
cIMz/RUIMe/EAsNeiwzEteHAtf/WpMs+OfF94SIUrDlkPr0H0H3DER8l1HZAvE0e
eD3ZJ6njrF6UHQWDVrekSTB0clpVTTU9TMpe+gs2nnFww9G8As+WsW8xHVjVipJy
AwqBhiR+s7wlcbh2i0NQqt8GL9/jIFTmleiwsQIDAQABAoIBAHNyP8pgl/yyzKzk
/0871wUBMTQ7zji91dGCaFtJM0HrcDK4D/uOOPEv7nE1qDpKPLr5Me1pHUS7+NGw
EAPtlNhgUtew2JfppdIwyi5qeOPADoi7ud6AH8xHsxg+IMwC+JuP8WhzyUHoJj9y
PRi/pX94Mvy9qdE25HqKddjx1mLdaHhxqPkr16/em23uYZqm1lORsCPD3vTlthj7
WiEbBSqmpYvjj8iFP4yFk2N+LvuWgSilRzq1Af3qE7PUp4xhjmcOPs78Sag1T7nl
ww/pgqCegISABHik7j++/5T+UlI5cLsyp/XENU9zAd4kCIczwNKpun2bn+djJdft
ravyX4ECgYEA+k2mHfi1zwKF3wT+cJbf30+uXrJczK2yZ33//4RKnhBaq7nSbQAI
nhWz2JESBK0TEo0+L7yYYq3HnT9vcES5R1NxzruH9wXgxssSx3JUj6w1raXYPh3B
+1XpYQsa6/bo2LmBELEx47F8FQbNgD5dmTJ4jBrf6MV4rRh9h6Bs7UkCgYEA4M3K
eAw52c2MNMIxH/LxdOQtEBq5GMu3AQC8I64DSSRrAoiypfEgyTV6S4gWJ5TKgYfD
zclnOVJF+tITe3neO9wHoZp8iCjCnoijcT6p2cJ4IaW68LEHPOokWBk0EpLjF4p2
7sFi9+lUpXYXfCN7aMJ77QpGzB7dNsBf0KUxMCkCgYEAjw/mjGbk82bLwUaHby6s
0mQmk7V6WPpGZ+Sadx7TzzglutVAslA8nK5m1rdEBywtJINaMcqnhm8xEm15cj+1
blEBUVnaQpQ3fyf+mcR9FIknPRL3X7l+b/sQowjH4GqFd6m/XR0KGMwO0a3Lsyry
MGeqgtmxdMe5S6YdyXEmERECgYAgQsgklDSVIh9Vzux31kh6auhgoEUh3tJDbZSS
Vj2YeIZ21aE1mTYISglj34K2aW7qSc56sMWEf18VkKJFHQccdgYOVfo7HAZZ8+fo
r4J2gqb0xTDfq7gLMNrIXc2QQM4gKbnJp60JQM3p9NmH8huavBZGvSvNzTwXyGG3
so0tiQKBgGQXZaxaXhYUcxYHuCkQ3V4Vsj3ezlM92xXlP32SGFm3KgFhYy9kATxw
Cax1ytZzvlrKLQyQFVK1COs2rHt7W4cJ7op7C8zXfsigXCiejnS664oAuX8sQZID
x3WQZRiXlWejSMUAHuMwXrhGlltF3lw83+xAjnqsVp75kGS6OH61
-----END RSA PRIVATE KEY-----`; // This key is invalidated. It’s from https://github.com/octokit/auth-app.js/issues/465#issuecomment-1564998327.

// Set up mocking
const mockAgent = new MockAgent();
mockAgent.disableNetConnect();
setGlobalDispatcher(mockAgent);
const mockPool = mockAgent.get("https://api.github.com");

// Calling `auth({ type: "app" })` to obtain a JWT doesn’t make network requests, so no need to intercept.

// Mock installation id request
const mockInstallationId = "123456";
mockPool
  .intercept({
    path: `/orgs/${process.env.INPUT_OWNER}/installation`,
    method: "GET",
    headers: {
      accept: "application/vnd.github.v3+json",
      "user-agent": "actions/create-github-app-token",
      // Intentionally omitting the `authorization` header, since JWT creation is not idempotent.
    },
  })
  .reply(
    200,
    { id: mockInstallationId },
    { headers: { "content-type": "application/json" } }
  );

// Mock installation access token request
const mockInstallationAccessToken = "ghs_16C7e42F292c6912E7710c838347Ae178B4a"; // This token is invalidated. It’s from https://docs.github.com/en/rest/apps/apps?apiVersion=2022-11-28#create-an-installation-access-token-for-an-app.
mockPool
  .intercept({
    path: `/app/installations/${mockInstallationId}/access_tokens`,
    method: "POST",
    headers: {
      accept: "application/vnd.github.v3+json",
      "user-agent": "actions/create-github-app-token",
      // Note: Intentionally omitting the `authorization` header, since JWT creation is not idempotent.
    },
  })
  .reply(201, { token: mockInstallationAccessToken });

// Run the main script
await import("../main.js");
