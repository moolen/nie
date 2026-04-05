# NIE Release Automation Design

## Goal

Automate GitHub Releases for `nie` so merges to `main` produce SemVer releases
derived from Conventional Commit messages and publish Linux `amd64` and
`arm64` artifacts via GoReleaser.

## Scope

This design covers:

- release version calculation from commit messages on `main`
- automatic creation of Git tags and GitHub Releases
- GoReleaser packaging for Linux `amd64` and `arm64`
- CI validation for GoReleaser configuration drift before changes land on
  `main`

This design does not introduce:

- package-manager publishing
- container image publishing
- non-Linux release artifacts
- manual release orchestration as the primary path

## Operator Model

The repository uses Conventional Commits as the release contract:

- `fix:` triggers a patch release
- `feat:` triggers a minor release
- `BREAKING CHANGE:` or `type!:` triggers a major release
- commits without releasable types do not create a release

On every push to `main`:

1. CI remains the merge gate and validates code plus release configuration.
2. A release workflow analyzes commits since the last release.
3. If there is no releasable change, the workflow exits cleanly.
4. If there is a releasable change, the workflow creates the next SemVer tag
   and GitHub Release.
5. GoReleaser builds and uploads Linux `amd64` and `arm64` release archives and
   checksums to that GitHub Release.

## Architecture

Use two release responsibilities:

1. `semantic-release` handles version calculation, changelog generation, tag
   creation, and GitHub Release creation.
2. GoReleaser handles artifact building, archive naming, and checksum
   generation for the created tag.

This separation matches the strengths of each tool:

- `semantic-release` is built to compute SemVer from Conventional Commits.
- GoReleaser expects a tag-driven release context and should not be forced to
  invent versions from branch history.

## Workflow Design

### Existing CI

Keep `.github/workflows/ci.yml` as the validation workflow for pushes and pull
requests.

Extend it to validate release configuration with a non-publishing GoReleaser
path:

- install GoReleaser in CI
- run `goreleaser check`
- run a snapshot build such as `goreleaser release --snapshot --clean`

This catches broken GoReleaser config, packaging regressions, and missing files
before merges hit `main`.

### Release Workflow

Add `.github/workflows/release.yml` triggered by pushes to `main`.

Requirements:

- `actions/checkout` with `fetch-depth: 0`
- repository write permissions sufficient for tags and releases
- one job for `semantic-release`
- one downstream tag-driven packaging path for GoReleaser

Recommended shape:

1. `semantic-release` runs on push to `main`
2. if no release is needed, workflow completes successfully
3. if a release is needed, it creates:
   - the next SemVer tag
   - GitHub Release notes/changelog
   - the GitHub Release object
4. a GoReleaser workflow triggered by tag push publishes artifacts for that tag

Using a tag-triggered GoReleaser workflow keeps packaging aligned with
GoReleaser's native expectations and makes re-runs deterministic for a given
tag.

## Repository Configuration

### Semantic Release

Add conventional release configuration in repository-local config such as:

- `.releaserc.json`, `.releaserc.yml`, or `package.json`

The configuration should:

- use the Conventional Commits analyzer
- generate release notes
- publish to GitHub
- target `main`

The repository does not need Node-based application code, but the release
workflow will still need a small Node environment because `semantic-release`
and its plugins are Node-based.

### GoReleaser

Add `.goreleaser.yaml` with:

- project name `nie`
- build target `./cmd/nie`
- `linux` as the only OS
- `amd64` and `arm64` as the target architectures
- archive packaging with stable names
- checksum generation

Artifacts should include:

- release archives for Linux `amd64`
- release archives for Linux `arm64`
- a checksum file

Archive contents should include the binary and the operator-facing files that
matter for initial use, such as:

- `README.md`
- `config.yaml`

If a license file is added later, it should also be included in the archive.

## Versioning Semantics

Version calculation is entirely commit-driven:

- no manual version bump files
- no requirement to create tags by hand
- the git tag created by `semantic-release` becomes the single release version
  source for GoReleaser

This keeps the release source of truth in git history and avoids duplicate
version declarations.

## Failure Handling

- Shallow history is treated as a configuration error; workflows must fetch full
  history.
- If `semantic-release` finds no releasable commits, the release workflow exits
  without creating tags or artifacts.
- If `semantic-release` creates a tag/release but GoReleaser fails, the
  workflow fails visibly and the release is left for operator follow-up rather
  than attempting automatic history rewrites.
- GoReleaser validation failures in CI block merges before they can reach the
  release path.

## Testing Strategy

Validation should happen in two layers.

### CI Validation

- run existing package and smoke coverage
- run `goreleaser check`
- run a snapshot GoReleaser build in CI to ensure archives can be assembled on
  Linux

### Release Validation

- verify that a releasable Conventional Commit on `main` produces a new SemVer
  tag
- verify that the release workflow uploads Linux `amd64` and `arm64` archives
  plus checksums
- verify that non-releasable commits on `main` do not create a release

## Security and Permissions

Keep permissions minimal:

- `contents: read` for normal CI
- `contents: write` for release workflows that create tags and GitHub Releases

No extra package registry or OIDC permissions are needed for this phase.

## Open Follow-Ups

These are intentionally deferred:

- enforcing Conventional Commits with a dedicated linting workflow
- signed release artifacts
- SBOM generation
- package-manager formulas or distribution packages
- container image release automation
