/**
 * Finds permissions passed via `permissions` and `permission-*` inputs and turns them into an object.
 *
 * @see https://docs.github.com/en/actions/sharing-automations/creating-actions/metadata-syntax-for-github-actions#inputs
 * @param {NodeJS.ProcessEnv} env
 * @returns {undefined | Record<string, string>}
 */
export function getPermissionsFromInputs(env) {
  const permissions = parsePermissionsInput(env.INPUT_PERMISSIONS);

  return Object.entries(env).reduce((permissions, [key, value]) => {
    if (!key.startsWith("INPUT_PERMISSION-")) return permissions;
    if (!value) return permissions;

    const permission = key.slice("INPUT_PERMISSION-".length).toLowerCase()
      .replaceAll(/-/g, "_");

    return {
      ...permissions,
      [permission]: value,
    };
  }, permissions);
}

/**
 * @param {string | undefined} input
 * @returns {undefined | Record<string, string>}
 */
function parsePermissionsInput(input) {
  if (!input) return undefined;

  return input.split(",").reduce((permissions, pair) => {
    const separatorIndex = pair.indexOf(":");
    const name = pair.slice(0, separatorIndex).trim();
    const level = pair.slice(separatorIndex + 1).trim();

    if (separatorIndex === -1 || !name || !level) {
      throw new Error(
        `Invalid permission '${pair.trim()}'. Expected 'permission-name: access-level'.`
      );
    }

    return {
      ...permissions,
      [name.replaceAll("-", "_")]: level,
    };
  }, {});
}
