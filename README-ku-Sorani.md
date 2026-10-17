# ALTIN POS

This branch contains the ALTIN sales and inventory system.

## Cloudflare Pages deployment

- Production branch: `altinn`
- Pages project: `altin-system`
- Static output directory: `deploy/`
- Cloudflare D1 binding: `DB` (database `workerjs`)

Both root copies and the `deploy/` copies are retained for convenient editing. The Cloudflare Pages output directory is `deploy`; update those deployed copies together when changing the app.

## Important safety notes

1. Back up the D1 database before deploying changes that touch production data.
2. Configure any required Pages secrets in Cloudflare; never commit API tokens or passwords.
3. The initial administrator secret, if needed for an empty database, is `ALTIN_INITIAL_ADMIN_PASSWORD` and must be set in Cloudflare Pages settings, not in GitHub source.
4. A commit to the production branch can trigger an automatic deployment once the Pages Git connection is active.

This commit publishes the source files to GitHub. A successful Git connection and live deployment must be confirmed separately in Cloudflare Pages.
