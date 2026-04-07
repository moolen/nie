# nie Cobra CLI Design

## Goal

Migrate `cmd/nie` from the standard library `flag` parser to `spf13/cobra` and
introduce an explicit `run` subcommand for starting the daemon.

## Scope

- replace ad-hoc `flag.FlagSet` parsing in `cmd/nie`
- add a Cobra root command and `run` subcommand
- require `--config` on `nie run`
- make bare `nie` show help instead of starting the daemon
- preserve the existing config loading, signal handling, and `internal/app.Run`
  wiring

No backwards compatibility is required for the previous `nie -config ...`
invocation shape.

## Design

### Command surface

- `nie`: prints help and exits successfully
- `nie run --config /path/to/config.yaml`: loads config and starts the daemon

### File layout

- `cmd/nie/main.go`
  - process entrypoint only
- `cmd/nie/root.go`
  - root command construction
  - shared dependency injection for tests
  - execution wrapper returning process exit codes
- `cmd/nie/run.go`
  - `run` command construction
  - `--config` flag registration
  - config load and `app.Run(...)` execution

### Error handling

- argument and validation failures return exit code `2`
- config read/load failures return exit code `1`
- runtime failures from `app.Run(...)` return exit code `1`
- Cobra usage text is suppressed for runtime/config errors to keep stderr clean

### Testing

Update `cmd/nie/main_test.go` to cover:

- bare `nie` prints help and returns `0`
- `nie run` without `--config` returns `2`
- config read failure is reported
- config load failure is reported
- `app.Run(...)` failure is reported

## Notes

This keeps the CLI layout conventional for future commands without introducing
an additional internal CLI package.
