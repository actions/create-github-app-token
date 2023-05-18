# `app-token-action`

> GitHub Action for creating a GitHub App Installation Access Token

## Usage

In order to use this action, you need to

1. [Register new GitHub App](#TBD)
2. [Store the App's ID in your repository environment variables](#TBD)
3. [Store the App's private key in your repository secrets](#TBD)

### Minimal usage

```yaml
on: [issues]

jobs:
  hello-world:
    runs-on: ubuntu-latest
    steps:
      - uses: gr2m/app-token-action@v1
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

### Limit the app's permissions and access to repositories

```yaml
on: [issues]

jobs:
  with-scoped-token:
    runs-on: ubuntu-latest
    steps:
      - uses: gr2m/app-token-action@v1
        id: app-token
        with:
          # required
          app_id: ${{ vars.APP_ID }}
          private_key: ${{ secrets.PRIVATE_KEY }}
          # optional: set permissions (#TBD)
          permissions_contents: write
          # optional: set repositories
          repositories: gr2m/my-repo1,gr2m/my-repo2
      # do something with the token
```

### Use app token with `actions/checkout`

```yaml
on: [pull_request]

jobs:
  auto-format:
    runs-on: ubuntu-latest
    steps:
      - uses: gr2m/app-token-action@v1
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

## How it works

TBD

- [ ] Find out if the created token can be revoked in the post step of the action

## License

[MIT](LICENSE)
