# SKILLS.md

Project conventions that skills/agents follow but aren't code. Currently: versioning & git workflow.

## Versioning & Git Workflow

### Gate

Before committing a completed plan/milestone, run:

```bash
corepack pnpm check
```

Must pass. No commit on red.

### Commit

Once green, commit everything with a [Conventional Commits](https://www.conventionalcommits.org/) message:

```
<type>(<scope>): <summary>

<body — why, not what>
```

Types: `feat`, `fix`, `refactor`, `docs`, `chore`, `test`, `ci`, `build`, `perf`. Scope = affected service (e.g. `parser-pipeline`, `alerting-engine`) or omit for repo-wide changes.

Breaking change: add `!` after type/scope (`feat(siem-core)!: ...`) and a `BREAKING CHANGE:` footer.

### Version bump (SemVer)

`MAJOR.MINOR.PATCH`, tracked wherever the repo's version lives (root `package.json` / `VERSION` file once one exists).

- **MAJOR** — breaking change (`!` commit, incompatible API/schema/config change)
- **MINOR** — new feature, backward-compatible (`feat`)
- **PATCH** — bug fix, backward-compatible (`fix`), or non-functional (`docs`, `chore`, `refactor` with no behavior change)

Foundation milestone (initial working stack) = `v0.1.0`.

### Tag

After commit, tag the release:

```bash
git tag -a vX.Y.Z -m "vX.Y.Z: <one-line summary>"
git push origin master --tags
```

One tag per milestone, not per commit. Tag only after the milestone's commits are in.

### When this runs

Triggered at the end of a plan/milestone — not per-commit during in-progress work. Mid-milestone commits are normal `git commit` without the version bump/tag step.
