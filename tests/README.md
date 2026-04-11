# Tests

Add one test file per scenario. You can run them in isolation with:

```
node tests/post-token-set.test.js
```

All tests are run together in [tests/index.js](index.js), which can be executed with Node's built-in test runner

```
node --test tests/index.js
```

or with npm

```
npm test
```

## How the tests work

The output from the tests is captured into a snapshot ([tests/index.js.snapshot](index.js.snapshot)). It includes all requests sent by our scripts to verify it's working correctly and to prevent regressions.

To update snapshots after an intentional change:

```
node --test --test-update-snapshots tests/index.js
```

## How to add a new test

We have tests both for the `main.js` and `post.js` scripts.

- If you do not expect an error, take [main-token-permissions-set.test.js](main-token-permissions-set.test.js) as a starting point.
- If your test has an expected error, take [main-missing-client-and-app-id.test.js](main-missing-client-and-app-id.test.js) as a starting point.
