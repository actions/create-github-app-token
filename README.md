# Create GitHub App Token

[![test](https://github.com/actions/create-github-app-token/actions/workflows/test.yml/badge.svg)](https://github.com/actions/create-github-app-token/actions/workflows/test.yml)

GitHub Action for creating a GitHub App installation access token.

## Usage

In order to use this action, you must first create a GitHub App. This is required in order to give create-github-app-token the necessary permissions to be able to generate tokens.

[See this page](https://docs.github.com/apps/creating-github-apps/setting-up-a-github-app/creating-a-github-app) for more details on how to register a GitHub App. Here are ways that you can create the app:
- [Use this link to create the GitHub app in your account](https://github.com/settings/apps/new?url=https://github.com/actions/create-github-app-token&webhook_active=false&public=false&metadata=read)
- [Use this link to create the GitHub app in your organization](https://github.com/organizations/:org/settings/apps/new?url=https://github.com/actions/create-github-app-token&webhook_active=false&public=false&metadata=read) (note: link will be dead and you must replace `:org` with your organization name)

The permissions that you give to the application depend on your use case:
- If you will use app tokens with `actions/checkout` to check out a private or internal repository (as described below), you will want to mark at least one permission under `Repository permissions` as read-only: `Contents`

Once you have the GitHub app installed, there are a few manual steps you must follow to finish setup:
1. In the `Private keys` section of your newly-created app, click `Generate a private key`. This will automatically trigger your web browser to download the private key .pem file, which will be used in step 4.
2. In the `Install app` section of your newly-created app, choose where you want to install the application. If installing into an Enterprise account, you would choose the organization(s) that you want to install your application into.
3. [Store the App's ID in your repository environment variables](https://docs.github.com/actions/learn-github-actions/variables#defining-configuration-variables-for-multiple-workflows) (example: `APP_ID`)
4. [Store the App's private key in your repository secrets](https://docs.github.com/actions/security-guides/encrypted-secrets?tool=webui#creating-encrypted-secrets-for-a-repository) (example: `PRIVATE_KEY`)

### Create a token for the current repository

```yaml
name: Run tests on staging
on:
  push:
    branches:
      - main

jobs:
  hello-world:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/create-github-app-token@v1
        id: app-token
        with:
          app-id: ${{ vars.APP_ID }}
          private-key: ${{ secrets.PRIVATE_KEY }}
          github-api-url: "https://github.acme-inc.com/api/v3"
      - uses: ./actions/staging-tests
        with:
          token: ${{ steps.app-token.outputs.token }}
```

### Use app token with `actions/checkout`

```yaml
on: [pull_request]

jobs:
  auto-format:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/create-github-app-token@v1
        id: app-token
        with:
          # required
          app-id: ${{ vars.APP_ID }}
          private-key: ${{ secrets.PRIVATE_KEY }}
      - uses: actions/checkout@v4
        with:
          token: ${{ steps.app-token.outputs.token }}
          ref: ${{ github.head_ref }}
          # Make sure the value of GITHUB_TOKEN will not be persisted in repo's config
          persist-credentials: false
      - uses: creyD/prettier_action@v4.3
        with:
          github_token: ${{ steps.app-token.outputs.token }}
```

### Create a token for all repositories in the current owner's installation

```yaml
on: [workflow_dispatch]

jobs:
  hello-world:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/create-github-app-token@v1
        id: app-token
        with:
          app-id: ${{ vars.APP_ID }}
          private-key: ${{ secrets.PRIVATE_KEY }}
          owner: ${{ github.repository_owner }}
      - uses: peter-evans/create-or-update-comment@v3
        with:
          token: ${{ steps.app-token.outputs.token }}
          issue-number: ${{ github.event.issue.number }}
          body: "Hello, World!"
```

### Create a token for multiple repositories in the current owner's installation

```yaml
on: [issues]

jobs:
  hello-world:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/create-github-app-token@v1
        id: app-token
        with:
          app-id: ${{ vars.APP_ID }}
          private-key: ${{ secrets.PRIVATE_KEY }}
          owner: ${{ github.repository_owner }}
          repositories: "repo1,repo2"
      - uses: peter-evans/create-or-update-comment@v3
        with:
          token: ${{ steps.app-token.outputs.token }}
          issue-number: ${{ github.event.issue.number }}
          body: "Hello, World!"
```

### Create a token for all repositories in another owner's installation

```yaml
on: [issues]

jobs:
  hello-world:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/create-github-app-token@v1
        id: app-token
        with:
          app-id: ${{ vars.APP_ID }}
          private-key: ${{ secrets.PRIVATE_KEY }}
          owner: another-owner
      - uses: peter-evans/create-or-update-comment@v3
        with:
          token: ${{ steps.app-token.outputs.token }}
          issue-number: ${{ github.event.issue.number }}
          body: "Hello, World!"
```

### Create tokens for multiple user or organization accounts

You can use a matrix strategy to create tokens for multiple user or organization accounts.

> [!NOTE]
> See [this documentation](https://docs.github.com/actions/using-workflows/workflow-commands-for-github-actions#multiline-strings) for information on using multiline strings in workflows.

```yaml
on: [workflow_dispatch]

jobs:
  set-matrix:
    runs-on: ubuntu-latest
    outputs:
      matrix: ${{steps.set.outputs.matrix }}
    steps:
      - id: set
        run: echo 'matrix=[{"owner":"owner1"},{"owner":"owner2","repos":["repo1"]}]' >>"$GITHUB_OUTPUT"

  use-matrix:
    name: "@${{ matrix.owners-and-repos.owner }} installation"
    needs: [set-matrix]
    runs-on: ubuntu-latest
    strategy:
      matrix:
        owners-and-repos: ${{ fromJson(needs.set-matrix.outputs.matrix) }}

    steps:
      - uses: actions/create-github-app-token@v1
        id: app-token
        with:
          app-id: ${{ vars.APP_ID }}
          private-key: ${{ secrets.PRIVATE_KEY }}
          owner: ${{ matrix.owners-and-repos.owner }}
          repositories: ${{ join(matrix.owners-and-repos.repos) }}
      - uses: octokit/request-action@v2.x
        id: get-installation-repositories
        with:
          route: GET /installation/repositories
        env:
          GITHUB_TOKEN: ${{ steps.app-token.outputs.token }}
      - run: echo "$MULTILINE_JSON_STRING"
        env:
          MULTILINE_JSON_STRING: ${{ steps.get-installation-repositories.outputs.data }}
```

### Run the workflow in a github.com repository against an organization in GitHub Enterprise Server

```yaml
on: [push]
```

## Inputs

### `app-id`

**Required:** GitHub App ID.

### `private-key`

**Required:** GitHub App private key.

### `owner`

**Optional:** GitHub App installation owner. If empty, defaults to the current repository owner.

### `repositories`

**Optional:** Comma-separated list of repositories to grant access to.

> [!NOTE]
> If `owner` is set and `repositories` is empty, access will be scoped to all repositories in the provided repository owner's installation. If `owner` and `repositories` are empty, access will be scoped to only the current repository.

### `skip-token-revoke`

**Optional:** If truthy, the token will not be revoked when the current job is complete.

### `github-api-url`

**Optional:** The URL of the GitHub REST API. Defaults to the URL of the GitHub Rest API where the workflow is run from.

## Outputs

### `token`

GitHub App installation access token.

## How it works

The action creates an installation access token using [the `POST /app/installations/{installation_id}/access_tokens` endpoint](https://docs.github.com/rest/apps/apps?apiVersion=2022-11-28#create-an-installation-access-token-for-an-app). By default,

1. The token is scoped to the current repository or `repositories` if set.
2. The token inherits all the installation's permissions.
3. The token is set as output `token` which can be used in subsequent steps.
4. Unless the `skip-token-revoke` input is set to a truthy value, the token is revoked in the `post` step of the action, which means it cannot be passed to another job.
5. The token is masked, it cannot be logged accidentally.

> [!NOTE]
> Installation permissions can differ from the app's permissions they belong to. Installation permissions are set when an app is installed on an account. When the app adds more permissions after the installation, an account administrator will have to approve the new permissions before they are set on the installation.

## License

[MIT](LICENSE)
