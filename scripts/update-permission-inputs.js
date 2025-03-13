import { readFile, writeFile } from "node:fs/promises";

import OctokitOpenapi from "@octokit/openapi";

const appPermissionsSchema =
  OctokitOpenapi.schemas["api.github.com"].components.schemas[
    "app-permissions"
  ];

await writeFile(
  `scripts/generated/app-permissions.json`,
  JSON.stringify(appPermissionsSchema, null, 2) + "\n",
  "utf8",
);

const permissionsInputs = Object.entries(appPermissionsSchema.properties)
  .sort((a, b) => a[0].localeCompare(b[0]))
  .reduce((result, [key, value]) => {
    const description = `Can be set to: ${value.enum
      .map((permission) => `'${permission}'`)
      .join(", ")}. ${value.description}`;
    return `${result}
  permission-${key.replace(/_/g, "-")}:
    description: "${description}"`;
  }, "");

const actionsYamlContent = await readFile("action.yml", "utf8");

// In the action.yml file, replace the content between the `<START GENERATED PERMISSIONS INPUTS>` and `<END GENERATED PERMISSIONS INPUTS>` comments with the new content
const updatedActionsYamlContent = actionsYamlContent.replace(
  /(?<=# <START GENERATED PERMISSIONS INPUTS>)(.|\n)*(?=# <END GENERATED PERMISSIONS INPUTS>)/,
  permissionsInputs + "\n  ",
);

await writeFile("action.yml", updatedActionsYamlContent, "utf8");
console.log("Updated action.yml with new permissions inputs");
