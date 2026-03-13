import { readFile, writeFile } from "node:fs/promises";

import OctokitOpenapi from "@octokit/openapi";

const appPermissionsSchema =
  OctokitOpenapi.schemas["api.github.com"].components.schemas[
    "app-permissions"
  ];

await writeFile(
  `scripts/generated/app-permissions.json`,
  JSON.stringify(appPermissionsSchema, null, 2) + "\n",
  "utf8"
);

const extraPermissions = {
  attestations: {
    type: "string",
    description:
      "The level of permission to grant the access token to create and manage GitHub attestations.",
    enum: ["read", "write"],
  },
  "organization-variables": {
    type: "string",
    description:
      "The level of permission to grant the access token to manage organization variables.",
    enum: ["read", "write"],
  },
  variables: {
    type: "string",
    description:
      "The level of permission to grant the access token to manage GitHub Actions configuration variables.",
    enum: ["read", "write"],
  },
};

const permissionsInputs = Object.entries({
  ...appPermissionsSchema.properties,
  ...extraPermissions,
})
  .sort((a, b) => a[0].localeCompare(b[0]))
  .reduce((result, [key, value]) => {
    const formatter = new Intl.ListFormat("en", {
      style: "long",
      type: "disjunction",
    });
    const permissionAccessValues = formatter.format(
      value.enum.map((p) => `'${p}'`)
    );

    const description = `${value.description} Can be set to ${permissionAccessValues}.`;
    return `${result}
  permission-${key.replace(/_/g, "-")}:
    description: "${description}"`;
  }, "");

const actionsYamlContent = await readFile("action.yml", "utf8");

// In the action.yml file, replace the content between the `<START GENERATED PERMISSIONS INPUTS>` and `<END GENERATED PERMISSIONS INPUTS>` comments with the new content
const updatedActionsYamlContent = actionsYamlContent.replace(
  /(?<=# <START GENERATED PERMISSIONS INPUTS>)(.|\n)*(?=# <END GENERATED PERMISSIONS INPUTS>)/,
  permissionsInputs + "\n  "
);

await writeFile("action.yml", updatedActionsYamlContent, "utf8");
console.log("Updated action.yml with new permissions inputs");
