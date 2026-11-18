import assert from "node:assert/strict";

import { getPermissionsFromInputs } from "../lib/get-permissions-from-inputs.js";

assert.equal(getPermissionsFromInputs({}), undefined);

assert.deepEqual(
  getPermissionsFromInputs({
    INPUT_PERMISSIONS: "contents: read,pull-requests: write",
    "INPUT_PERMISSION-CONTENTS": "write",
  }),
  {
    contents: "write",
    pull_requests: "write",
  }
);

for (const input of ["contents", ": read", "contents: "]) {
  assert.throws(
    () => getPermissionsFromInputs({ INPUT_PERMISSIONS: input }),
    /Expected 'permission-name: access-level'/
  );
}