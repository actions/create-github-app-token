# Create GitHub App Token

[![test](https://github.com/actions/create-github-app-token/actions/workflows/test.yml/badge.svg)](https://github.com/actions/create-github-app-token/actions/workflows/test.yml)

GitHub Action for creating a GitHub App installation access token using AWS KMS in order to safely store the GitHub repositry private key.

## Usage

In order to use this action, you need to:

1. [Register new GitHub App](https://docs.github.com/apps/creating-github-apps/setting-up-a-github-app/creating-a-github-app)
2. [Store the App's ID in your repository environment variable](https://docs.github.com/actions/learn-github-actions/variables#defining-configuration-variables-for-multiple-workflows) or [secret](https://docs.github.com/actions/security-guides/encrypted-secrets?tool=webui#creating-encrypted-secrets-for-a-repository) (example: `APP_ID`)
3. [Import the App's private key in your AWS Account KMS service, under customer-managed keys of type assymetric, sign-verify](https://docs.aws.amazon.com/kms/latest/developerguide/importing-keys-create-cmk.html)
4. [Store the above KMS Key ID as a repository secret](https://docs.github.com/actions/security-guides/encrypted-secrets?tool=webui#creating-encrypted-secrets-for-a-repository) (example `KMS_KEY_ID`). Once stored in AWS KMS, the GitHub private key can no longer be retieved from AWS. AWS API can only by asked to sign/verify using the respective key. This substantially improves the security posture, because the key is no longer accessible.
5. [Store the AWS role to be assumed by the action as a repository secret](https://docs.github.com/actions/security-guides/encrypted-secrets?tool=webui#creating-encrypted-secrets-for-a-repository) (example `ROLE_TO_ASSUME`)
6. [Store the AWS session name as an environment_variable](https://docs.github.com/actions/learn-github-actions/variables#defining-configuration-variables-for-multiple-workflows) (example `ROLE_SESSION_NAME`)
7. [Store the AWS region name as an environment_variable](https://docs.github.com/actions/learn-github-actions/variables#defining-configuration-variables-for-multiple-workflows) (example `AWS_REGION`)

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
      - name: AWS Login
        uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-region: ${{ vars.AWS_REGION }}
          role-to-assume: ${{ secrets.ROLE_TO_ASSUME }}
          role-session-name: ${{ vars.ROLE_SESSION_NAME }}
      - uses: actions/create-github-app-token@v1
        id: app-token
        with:
          app-id: ${{ vars.APP_ID }}
          kms-key-id: ${{ secrets.KMS_KEY_ID }}
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
      - name: AWS Login
        uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-region: ${{ vars.AWS_REGION }}
          role-to-assume: ${{ secrets.ROLE_TO_ASSUME }}
          role-session-name: ${{ vars.ROLE_SESSION_NAME }}
      - uses: actions/create-github-app-token@v1
        id: app-token
        with:
          # required
          app-id: ${{ vars.APP_ID }}
          kms-key-id: ${{ secrets.KMS_KEY_ID }}
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
      - name: AWS Login
        uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-region: ${{ vars.AWS_REGION }}
          role-to-assume: ${{ secrets.ROLE_TO_ASSUME }}
          role-session-name: ${{ vars.ROLE_SESSION_NAME }}
      - uses: actions/create-github-app-token@v1
        id: app-token
        with:
          # required
          app-id: ${{ vars.APP_ID }}
          kms-key-id: ${{ secrets.KMS_KEY_ID }}
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
      - name: AWS Login
        uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-region: ${{ vars.AWS_REGION }}
          role-to-assume: ${{ secrets.ROLE_TO_ASSUME }}
          role-session-name: ${{ vars.ROLE_SESSION_NAME }}
      - uses: actions/create-github-app-token@v1
        id: app-token
        with:
          # required
          app-id: ${{ vars.APP_ID }}
          kms-key-id: ${{ secrets.KMS_KEY_ID }}
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
      - name: AWS Login
        uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-region: ${{ vars.AWS_REGION }}
          role-to-assume: ${{ secrets.ROLE_TO_ASSUME }}
          role-session-name: ${{ vars.ROLE_SESSION_NAME }}
      - uses: actions/create-github-app-token@v1
        id: app-token
        with:
          app-id: ${{ vars.APP_ID }}
          kms-key-id: ${{ secrets.KMS_KEY_ID }}
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
      - name: AWS Login
        uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-region: ${{ vars.AWS_REGION }}
          role-to-assume: ${{ secrets.ROLE_TO_ASSUME }}
          role-session-name: ${{ vars.ROLE_SESSION_NAME }}
      - uses: actions/create-github-app-token@v1
        id: app-token
        with:
          app-id: ${{ vars.APP_ID }}
          kms-key-id: ${{ secrets.KMS_KEY_ID }}
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
      - name: AWS Login
        uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-region: ${{ vars.AWS_REGION }}
          role-to-assume: ${{ secrets.ROLE_TO_ASSUME }}
          role-session-name: ${{ vars.ROLE_SESSION_NAME }}
      - uses: actions/create-github-app-token@v1
        id: app-token
        with:
          app-id: ${{ vars.APP_ID }}
          kms-key-id: ${{ secrets.KMS_KEY_ID }}
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
      - name: AWS Login
        uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-region: ${{ vars.AWS_REGION }}
          role-to-assume: ${{ secrets.ROLE_TO_ASSUME }}
          role-session-name: ${{ vars.ROLE_SESSION_NAME }}
      - uses: actions/create-github-app-token@v1
        id: app-token
        with:
          app-id: ${{ vars.APP_ID }}
          kms-key-id: ${{ secrets.KMS_KEY_ID }}
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
    - name: AWS Login
        uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-region: ${{ vars.AWS_REGION }}
          role-to-assume: ${{ secrets.ROLE_TO_ASSUME }}
          role-session-name: ${{ vars.ROLE_SESSION_NAME }}
    - name: Create GitHub App token
      id: create_token
      uses: actions/create-github-app-token@v1
      with:
        app-id: ${{ vars.GHES_APP_ID }}
        kms-key-id: ${{ secrets.KMS_KEY_ID }}
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

### `kms-key-id`

**Required:** AWS KMS Key ID that is imported from GitHub.

### `owner`

**Optional:** The owner of the GitHub App installation. If empty, defaults to the current repository owner.

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

### `installation-id`

GitHub App installation ID.

### `app-slug`

GitHub App slug.

## How it works

The action creates an installation access token using [the `POST /app/installations/{installation_id}/access_tokens` endpoint](https://docs.github.com/rest/apps/apps?apiVersion=2022-11-28#create-an-installation-access-token-for-an-app). 

The action uses the GitHub private key stored in AWS KMS so sign a JWT token and uses this token subsequently for autheticating each GitHub API call, including the one above. Once stored in AWS KMS, the GitHub private key can no longer be retieved from AWS. AWS API can only by asked to sign/verify using the respective key.  This substantially improves the security posture, because the action will no longer access the private key anymore, but ask AWS API to sign/verify instead. 

By default,

1. The token is scoped to the current repository or `repositories` if set.
2. The token inherits all the installation's permissions.
3. The token is set as output `token` which can be used in subsequent steps.
4. Unless the `skip-token-revoke` input is set to a truthy value, the token is revoked in the `post` step of the action, which means it cannot be passed to another job.
5. The token is masked, it cannot be logged accidentally.

> [!NOTE]
> Installation permissions can differ from the app's permissions they belong to. Installation permissions are set when an app is installed on an account. When the app adds more permissions after the installation, an account administrator will have to approve the new permissions before they are set on the installation.

## License

[MIT](LICENSE)
