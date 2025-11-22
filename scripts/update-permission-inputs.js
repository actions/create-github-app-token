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

const permissionsInputs = Object.entries(appPermissionsSchema.properties)
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

const actionYamlContent = await readFile("action.yml", "utf8");

// In the action.yml file, replace the content between the `<START GENERATED PERMISSIONS INPUTS>` and `<END GENERATED PERMISSIONS INPUTS>` comments with the new content
const updatedActionYamlContent = actionYamlContent.replace(
  /(?<=# <START GENERATED PERMISSIONS INPUTS>)(.|\n)*(?=# <END GENERATED PERMISSIONS INPUTS>)/,
  permissionsInputs + "\n  "
);

await writeFile("action.yml", updatedActionYamlContent, "utf8");
console.log("Updated action.yml with new permissions inputs");

const permissionsTypes = Object.entries(appPermissionsSchema.properties)
  .sort((a, b) => a[0].localeCompare(b[0]))
  .reduce((result, [key, value]) => {
    const permissionAccessValues = value.enum.map((p) => `      - "${p}"`).reduce((result, p) => `${result}\n${p}`);
    return `${result}
  permission-${key.replace(/_/g, "-")}:
    type: enum
    allowed-values:
${permissionAccessValues}
`;
  }, "");

const actionTypesYamlContent = await readFile("action-types.yml", "utf8");

// In the action-types.yml file, replace the content between the `<START GENERATED PERMISSIONS TYPES>` and `<END GENERATED PERMISSIONS TYPES>` comments with the new content
const updatedActionTypesYamlContent = actionTypesYamlContent.replace(
  /(?<=# <START GENERATED PERMISSIONS TYPES>)(.|\n)*(?=# <END GENERATED PERMISSIONS TYPES>)/,
  permissionsTypes + "\n  "
);

await writeFile("action-types.yml", updatedActionTypesYamlContent, "utf8");
console.log("Updated action-types.yml with new permissions types");
