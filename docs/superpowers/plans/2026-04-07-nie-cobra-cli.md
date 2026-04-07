# nie Cobra CLI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Migrate `cmd/nie` to `spf13/cobra` and add `nie run --config ...` as the explicit runtime entrypoint.

**Architecture:** Keep `cmd/nie` as a thin CLI layer. The root command owns help and execution plumbing, while a dedicated `run` command owns config parsing and the call into `internal/app.Run(...)`.

**Tech Stack:** Go 1.24, `spf13/cobra`, `testing`, existing `internal/config` and `internal/app`

---

### Task 1: Lock in CLI behavior with tests

**Files:**
- Modify: `cmd/nie/main_test.go`
- Test: `cmd/nie/main_test.go`

- [ ] **Step 1: Write failing tests for Cobra behavior**

Add tests for:
- bare `nie` returns `0` and prints help text
- `nie run` without `--config` returns `2`
- existing config read/load/runtime error paths still report on stderr

- [ ] **Step 2: Run package tests to verify they fail**

Run: `go test ./cmd/nie`
Expected: FAIL because the CLI still uses `flag` and has no `run` subcommand

### Task 2: Implement Cobra command tree

**Files:**
- Modify: `cmd/nie/main.go`
- Create: `cmd/nie/root.go`
- Create: `cmd/nie/run.go`
- Modify: `go.mod`
- Modify: `go.sum`

- [ ] **Step 1: Add `spf13/cobra` dependency**

Run: `go get github.com/spf13/cobra@latest`
Expected: `go.mod` and `go.sum` updated

- [ ] **Step 2: Add root command execution wrapper**

Implement a root command that:
- uses `Use: "nie"`
- prints help when invoked without subcommands
- executes a `run` subcommand
- converts Cobra argument/validation errors to exit code `2`

- [ ] **Step 3: Add `run` subcommand**

Implement a `run` command that:
- registers required `--config`
- loads YAML config from disk
- builds signal-aware context
- calls `app.Run(ctx, cfg, logger)`

- [ ] **Step 4: Re-run package tests**

Run: `go test ./cmd/nie`
Expected: PASS

### Task 3: Update user-facing docs and verify build

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Update README command examples**

Document that daemon startup now uses `nie run --config ...`.

- [ ] **Step 2: Run targeted verification**

Run: `go test ./cmd/nie ./internal/app`
Expected: PASS

- [ ] **Step 3: Run broader verification**

Run: `go test ./...`
Expected: PASS or a clear report of unrelated/environment-specific failures
