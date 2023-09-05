// state variables are set as environment variables with the prefix STATE_
// https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions#sending-values-to-the-pre-and-post-actions
delete process.env.STATE_token;

await import("../post.js");
