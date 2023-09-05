# Tests

Add one test file per scenario. You can run them in isolation with:

```bash
node tests/post-token-set.test.js
```

All tests are run together in [tests/index.js](index.js), which can be execauted with ava

```
npx ava tests/index.js
```

or with npm

```
npm test
```
