# Tests

Add one test file per scenario. You can run them in isolation with:

```bash
node tests/post-token-set.test.js
```

All tests are run together in [tests/index.js](index.js), which can be executed with ava

```
npx ava tests/index.js
```

or with npm

```
npm test
```

## How the tests work

The output from the tests is captured into a snapshot ([tests/snapshots/index.js.md](snapshots/index.js.md)). It includes all requests sent by our scripts to verify it's working correctly and to prevent regressions.

## How to add a new test

We have tests both for the `main.js` and `post.js` scripts.

- If you do not expect an error, take [main-token-permissions-set.test.js](tests/main-token-permissions-set.test.js) as a starting point.
- If your test has an expected error, take [main-missing-app-id.test.js](tests/main-missing-app-id.test.js) as a starting point.
