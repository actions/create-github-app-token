import { readFile, writeFile } from "node:fs/promises";

import { request } from "@octokit/request";

const { data: permissionsSchemaString } = await request(
  "GET /repos/{owner}/{repo}/contents/{path}",
  {
    owner: "octokit",
    repo: "app-permissions",
    path: "generated/api.github.com.json",
    mediaType: {
      format: "raw",
    },
    headers: {
      authorization: `token ${process.env.GITHUB_TOKEN}`,
    },
  },
);

const permissionsSchema = JSON.parse(permissionsSchemaString);

const permissionsInputs = Object.entries(permissionsSchema.permissions).reduce(
  (result, [key, value]) => {
    const supportsWrite = value.write.length > 0;
    const description = supportsWrite
      ? `Can be set to 'read' or 'write'. Learn more at ${value.url}`
      : `Can be set to 'read'. Learn more at ${value.url}`;
    return `${result}
  permission-${key.replace(/_/g, "-")}:
    description: "${description}"`;
  },
  "",
);

const actionsYamlContent = await readFile("action.yml", "utf8");

// In the action.yml file, replace the content between the `<START GENERATED PERMISSIONS INPUTS>` and `<END GENERATED PERMISSIONS INPUTS>` comments with the new content
const updatedActionsYamlContent = actionsYamlContent.replace(
  /(?<=# <START GENERATED PERMISSIONS INPUTS>)(.|\n)*(?=# <END GENERATED PERMISSIONS INPUTS>)/,
  permissionsInputs + "\n  ",
);

await writeFile("action.yml", updatedActionsYamlContent, "utf8");
console.log("Updated action.yml with new permissions inputs");
