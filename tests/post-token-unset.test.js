// state variables are set as environment variables with the prefix STATE_
// https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions#sending-values-to-the-pre-and-post-actions
delete process.env.STATE_token;

// inputs are set as environment variables with the prefix INPUT_
// https://docs.github.com/en/actions/creating-actions/metadata-syntax-for-github-actions#example-specifying-inputs
process.env["INPUT_SKIP-TOKEN-REVOKE"] = "false";
process.env["INPUT_SKIP_TOKEN_REVOKE"] = "false";

await import("../post.js");
