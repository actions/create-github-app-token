# Create GitHub App Token

[![test](https://github.com/actions/create-github-app-token/actions/workflows/test.yml/badge.svg)](https://github.com/actions/create-github-app-token/actions/workflows/test.yml)

GitHub Action for creating a GitHub App installation access token.

## Usage

In order to use this action, you need to:

1. [Register new GitHub App](https://docs.github.com/apps/creating-github-apps/setting-up-a-github-app/creating-a-github-app)
2. [Store the App's ID in your repository environment variables](https://docs.github.com/actions/learn-github-actions/variables#defining-configuration-variables-for-multiple-workflows) (example: `APP_ID`)
3. [Store the App's private key in your repository secrets](https://docs.github.com/actions/security-guides/encrypted-secrets?tool=webui#creating-encrypted-secrets-for-a-repository) (example: `PRIVATE_KEY`)

> [!IMPORTANT]  
> An installation access token expires after 1 hour. Please [see this comment](https://github.com/actions/create-github-app-token/issues/121#issuecomment-2043214796) for alternative approaches if you have long-running processes.

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

### Create a git committer string for an app installation

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
      - name: Get GitHub App User ID
        id: get-user-id
        run: echo "user-id=$(gh api "/users/${{ steps.app-token.outputs.app-slug }}[bot]" --jq .id)" >> "$GITHUB_OUTPUT"
        env:
          GH_TOKEN: ${{ steps.app-token.outputs.token }}
      - id: committer
        run: echo "string=${{ steps.app-token.outputs.app-slug }}[bot] <${{ steps.get-user-id.outputs.user-id }}+${{ steps.app-token.outputs.app-slug }}[bot]@users.noreply.github.com>"  >> "$GITHUB_OUTPUT"
      - run: echo "committer string is ${ {steps.committer.outputs.string }}"
```

### Configure git CLI for an app's bot user

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
      - name: Get GitHub App User ID
        id: get-user-id
        run: echo "user-id=$(gh api "/users/${{ steps.app-token.outputs.app-slug }}[bot]" --jq .id)" >> "$GITHUB_OUTPUT"
        env:
          GH_TOKEN: ${{ steps.app-token.outputs.token }}
      - run: |
          git config --global user.name '${{ steps.app-token.outputs.app-slug }}[bot]'
          git config --global user.email '${{ steps.get-user-id.outputs.user-id }}+${{ steps.app-token.outputs.app-slug }}[bot]@users.noreply.github.com>'
      # git commands like commit work using the bot user
      - run: |
          git add .
          git commit -m "Auto-generated changes"
          git push
```

> [!TIP]
> The `<BOT USER ID>` is the numeric user ID of the app's bot user, which can be found under `https://api.github.com/users/<app-slug>%5Bbot%5D`.
> 
> For example, we can check at `https://api.github.com/users/dependabot[bot]` to see the user ID of Dependabot is 49699333.
>
> Alternatively, you can use the [octokit/request-action](https://github.com/octokit/request-action) to get the ID.

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
          repositories: |
            repo1
            repo2
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
      matrix: ${{ steps.set.outputs.matrix }}
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

jobs:
  create_issue:
    runs-on: self-hosted

    steps:
    - name: Create GitHub App token
      id: create_token
      uses: actions/create-github-app-token@v1
      with:
        app-id: ${{ vars.GHES_APP_ID }}
        private-key: ${{ secrets.GHES_APP_PRIVATE_KEY }}
        owner: ${{ vars.GHES_INSTALLATION_ORG }}
        github-api-url: ${{ vars.GITHUB_API_URL }}

    - name: Create issue
      uses: octokit/request-action@v2.x
      with:
        route: POST /repos/${{ github.repository }}/issues
        title: "New issue from workflow"
        body: "This is a new issue created from a GitHub Action workflow."
      env:
        GITHUB_TOKEN: ${{ steps.create_token.outputs.token }}
```

## Inputs

### `app-id`

**Required:** GitHub App ID.

### `private-key`

**Required:** GitHub App private key. Escaped newlines (`\\n`) will be automatically replaced with actual newlines.

Some other actions may require the private key to be Base64 encoded. To avoid recreating a new secret, it can be decoded on the fly, but it needs to be managed securely. Here is an example of how this can be achieved:

```yaml
steps:
  - name: Decode the GitHub App Private Key
    id: decode
    run: |
      private_key=$(echo "${{ secrets.PRIVATE_KEY }}" | base64 -d | awk 'BEGIN {ORS="\\n"} {print}' | head -c -2) &> /dev/null
      echo "::add-mask::$private_key"
      echo "private-key=$private_key" >> "$GITHUB_OUTPUT"
  - name: Generate GitHub App Token
    id: app-token
    uses: actions/create-github-app-token@v1
    with:
      app-id: ${{ vars.APP_ID }}
      private-key: ${{ steps.decode.outputs.private-key }}
```

### `owner`

**Optional:** The owner of the GitHub App installation. If empty, defaults to the current repository owner.

### `repositories`

**Optional:** Comma or newline-separated list of repositories to grant access to.

> [!NOTE]
> If `owner` is set and `repositories` is empty, access will be scoped to all repositories in the provided repository owner's installation. If `owner` and `repositories` are empty, access will be scoped to only the current repository.

### `skip-token-revoke`

**Optional:** If truthy, the token will not be revoked when the current job is complete.

### `github-api-url`

**Optional:** The URL of the GitHub REST API. Defaults to the URL of the GitHub Rest API where the workflow is run from.

## Outputs

### `token`

GitHub App installation access token.

### `installation-id`

GitHub App installation ID.

### `app-slug`

GitHub App slug.

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
