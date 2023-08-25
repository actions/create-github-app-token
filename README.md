# Create GitHub App Token

GitHub Action for creating a GitHub App installation access token.

## Usage

In order to use this action, you need to:

1. [Register new GitHub App](https://docs.github.com/apps/creating-github-apps/setting-up-a-github-app/creating-a-github-app)
2. [Store the App's ID in your repository environment variables](https://docs.github.com/actions/learn-github-actions/variables#defining-configuration-variables-for-multiple-workflows) (example: `APP_ID`)
3. [Store the App's private key in your repository secrets](https://docs.github.com/actions/security-guides/encrypted-secrets?tool=webui#creating-encrypted-secrets-for-a-repository) (example: `PRIVATE_KEY`)

### Minimal usage

```yaml
on: [issues]

jobs:
  hello-world:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/create-github-app-token@v1
        id: app-token
        with:
          app_id: ${{ vars.APP_ID }}
          private_key: ${{ secrets.PRIVATE_KEY }}
      - uses: peter-evans/create-or-update-comment@v3
        with:
          token: ${{ steps.app-token.outputs.token }}
          issue-number: ${{ github.event.issue.number }}
          body: "Hello, World!"
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
          app_id: ${{ vars.APP_ID }}
          private_key: ${{ secrets.PRIVATE_KEY }}
      - uses: actions/checkout@v3
        with:
          token: ${{ steps.app-token.outputs.token }}
          ref: ${{ github.head_ref }}
          # Make sure the value of GITHUB_TOKEN will not be persisted in repo's config
          persist-credentials: false
      - uses: creyD/prettier_action@v4.3
        with:
          github_token: ${{ steps.app-token.outputs.token }}
```

## Inputs

### `app_id`

**Required:** GitHub App ID.

### `private_key`

**Required:** GitHub App private key.

## Outputs

### `token`

GitHub App installation access token.

## How it works

The action creates an installation access token using [the `POST /app/installations/{installation_id}/access_tokens` endpoint](https://docs.github.com/rest/apps/apps?apiVersion=2022-11-28#create-an-installation-access-token-for-an-app). By default,

1. The token is scoped to the current repository.
2. The token inherits all the installation's permissions.
3. The token is set as output `token` which can be used in subsequent steps.
4. The token is revoked in the `post` step of the action, which means it cannot be passed to another job.
5. The token is masked, it cannot be logged accidentally.

> [!NOTE]
> Installation permissions can differ from the app's permissions they belong to. Installation permissions are set when an app is installed on an account. When the app adds more permissions after the installation, an account administrator will have to approve the new permissions before they are set on the installation.

## License

[MIT](LICENSE)
