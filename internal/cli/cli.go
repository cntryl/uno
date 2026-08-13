package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/cntryl/uno/internal/core/engine"
	"github.com/cntryl/uno/internal/core/provider"
	"github.com/cntryl/uno/internal/core/secret"
	tpl "github.com/cntryl/uno/internal/core/template"
	"github.com/cntryl/uno/internal/devguard"
	"github.com/cntryl/uno/internal/dotenv"
	buildversion "github.com/cntryl/uno/internal/version"
)

const version = buildversion.Current

type app struct {
	templatePath string
	registry     *provider.Registry
	timeout      time.Duration
	runtime      Runtime
}

// Runtime supplies all process and environment boundaries used by commands.
type Runtime struct {
	Stdin      io.Reader
	Stdout     io.Writer
	Stderr     io.Writer
	Environ    func() []string
	LookupEnv  func(string) (string, bool)
	ReadFile   func(string) ([]byte, error)
	IsTerminal func(io.Reader) bool
	Command    func(context.Context, string, ...string) *exec.Cmd
}

// DefaultRuntime connects command orchestration to the current process.
func DefaultRuntime() Runtime {
	return Runtime{
		Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr,
		Environ: os.Environ, LookupEnv: os.LookupEnv, ReadFile: os.ReadFile,
		IsTerminal: func(in io.Reader) bool { file, ok := in.(*os.File); return ok && isInteractive(file) },
		Command:    exec.CommandContext,
	}
}

func (runtime Runtime) withDefaults() Runtime {
	defaults := DefaultRuntime()
	if runtime.Stdin == nil {
		runtime.Stdin = defaults.Stdin
	}
	if runtime.Stdout == nil {
		runtime.Stdout = defaults.Stdout
	}
	if runtime.Stderr == nil {
		runtime.Stderr = defaults.Stderr
	}
	if runtime.Environ == nil {
		runtime.Environ = defaults.Environ
	}
	if runtime.LookupEnv == nil {
		runtime.LookupEnv = defaults.LookupEnv
	}
	if runtime.ReadFile == nil {
		runtime.ReadFile = defaults.ReadFile
	}
	if runtime.IsTerminal == nil {
		runtime.IsTerminal = defaults.IsTerminal
	}
	if runtime.Command == nil {
		runtime.Command = defaults.Command
	}
	return runtime
}

// ExecuteWithRegistry runs one command. Named results let its deferred
// classifier apply consistent exit codes without duplicated error wrapping.
func ExecuteWithRegistry(ctx context.Context, args []string, providers *provider.Registry) (code int, err error) { //nolint:nonamedreturns
	return Execute(ctx, args, providers, DefaultRuntime())
}

// Execute runs one command with injected process boundaries.
func Execute(ctx context.Context, args []string, providers *provider.Registry, runtime Runtime) (code int, err error) { //nolint:nonamedreturns
	defer func() {
		if err == nil {
			return
		}
		code = 1
		message := err.Error()
		for _, marker := range []string{"invalid arguments:", "unknown command ", "a command is required", " does not accept ", "run requires a command"} {
			if strings.Contains(message, marker) {
				code = 2
				return
			}
		}
	}()
	a := &app{registry: providers, runtime: runtime.withDefaults()}
	global := flag.NewFlagSet("uno", flag.ContinueOnError)
	global.SetOutput(io.Discard)
	global.StringVar(&a.templatePath, "template", "", "secrets template path")
	global.DurationVar(&a.timeout, "timeout", 60*time.Second, "provider operation timeout")
	help, showVersion := false, false
	global.BoolVar(&help, "help", false, "show help")
	global.BoolVar(&help, "h", false, "show help")
	global.BoolVar(&showVersion, "version", false, "show version")
	invocation, err := parseInvocation(args, global)
	if err != nil {
		return 0, err
	}
	if !invocation.commandFound {
		if err := global.Parse(invocation.globals); err != nil {
			return 0, cleanFlagError(err)
		}
		if showVersion {
			_, _ = fmt.Fprintf(a.runtime.Stdout, "uno %s\n", version)
			return 0, nil
		}
		if help || len(args) == 0 {
			printHelp(a.runtime.Stdout)
			return 0, nil
		}
		return 0, fmt.Errorf("a command is required")
	}
	command, commandArgs := invocation.command, invocation.commandArgs
	if err := global.Parse(invocation.globals); err != nil {
		return 0, cleanFlagError(err)
	}
	if a.timeout <= 0 {
		return 0, fmt.Errorf("invalid arguments: timeout must be greater than zero")
	}
	if command != "check" && command != "sync" && command != "dev" && command != "run" && command != "rollback" {
		return 0, fmt.Errorf("unknown command %q", command)
	}
	// For "run", --help/--version short-circuit unless there's a leftover
	// positional argument suggesting the user forgot the "--" separator
	// (e.g. "run somecmd --version" should error, not print the version).
	// A flag given before the command name (helpBeforeCommand/
	// versionBeforeCommand) is always an explicit, unambiguous request and
	// wins regardless of what follows.
	if (help || showVersion) && (command != "run" || invocation.runHasSeparator || len(commandArgs) == 0 ||
		invocation.helpBeforeCommand || invocation.versionBeforeCommand) {
		if showVersion {
			_, _ = fmt.Fprintf(a.runtime.Stdout, "uno %s\n", version)
		} else {
			printCommandHelp(a.runtime.Stdout, command)
		}
		return 0, nil
	}
	if command == "run" && (!invocation.runHasSeparator || len(commandArgs) < 2 || commandArgs[0] != "--") {
		return 0, fmt.Errorf("run requires a command after --")
	}
	switch command {
	case "check":
		fs := flag.NewFlagSet("check", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		if err := fs.Parse(commandArgs); err != nil {
			return 0, cleanFlagError(err)
		}
		if fs.NArg() != 0 {
			return 0, fmt.Errorf("check does not accept arguments")
		}
		plan, err := a.load()
		if err != nil {
			return 0, err
		}
		_, _ = fmt.Fprintf(a.runtime.Stdout, "template valid: %d mappings\n", len(plan.Mappings))
		return 0, nil
	case "sync":
		fs := flag.NewFlagSet("sync", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		dry := fs.Bool("dry-run", false, "resolve and inspect without confirming or writing")
		force := fs.Bool("force", false, "write pending changes without an interactive confirmation")
		jsonOut := fs.Bool("json", false, "print machine-readable JSON output")
		if err := fs.Parse(commandArgs); err != nil {
			return 0, cleanFlagError(err)
		}
		if fs.NArg() != 0 {
			return 0, fmt.Errorf("sync does not accept positional arguments")
		}
		plan, err := a.load()
		if err != nil {
			return 0, err
		}
		opCtx, cancel := context.WithTimeout(ctx, a.timeout)
		defer cancel()
		result, err := engine.Sync(opCtx, plan, engine.SyncOptions{DryRun: *dry, Confirm: confirmSync(a.runtime, *force)})
		if *jsonOut {
			if jsonErr := printSyncResultJSON(a.runtime.Stdout, result, err); jsonErr != nil && err == nil {
				err = jsonErr
			}
		} else {
			printSyncResult(a.runtime.Stdout, result, err)
		}
		if errors.Is(opCtx.Err(), context.DeadlineExceeded) {
			return 0, fmt.Errorf("operation timed out")
		}
		return 0, err
	case "dev":
		fs := flag.NewFlagSet("dev", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		if err := fs.Parse(commandArgs); err != nil {
			return 0, cleanFlagError(err)
		}
		if fs.NArg() != 0 {
			return 0, fmt.Errorf("dev does not accept arguments")
		}
		plan, err := a.load()
		if err != nil {
			return 0, err
		}
		opCtx, cancel := context.WithTimeout(ctx, a.timeout)
		defer cancel()
		if err := devguard.Check(opCtx, "."); err != nil {
			if errors.Is(opCtx.Err(), context.DeadlineExceeded) {
				return 0, fmt.Errorf("operation timed out")
			}
			return 0, err
		}
		values, err := engine.Resolve(opCtx, plan)
		if err != nil {
			if errors.Is(opCtx.Err(), context.DeadlineExceeded) {
				return 0, fmt.Errorf("operation timed out")
			}
			return 0, err
		}
		defer secret.DestroyMap(values)
		if err := devguard.Check(opCtx, "."); err != nil {
			if errors.Is(opCtx.Err(), context.DeadlineExceeded) {
				return 0, fmt.Errorf("operation timed out")
			}
			return 0, err
		}
		if err := dotenv.Write(".env.secrets", values); err != nil {
			if errors.Is(opCtx.Err(), context.DeadlineExceeded) {
				return 0, fmt.Errorf("operation timed out")
			}
			return 0, err
		}
		if errors.Is(opCtx.Err(), context.DeadlineExceeded) {
			return 0, fmt.Errorf("operation timed out")
		}
		_, _ = fmt.Fprintf(a.runtime.Stdout, "wrote .env.secrets with %d secrets\n", len(values))
		return 0, nil
	case "run":
		commandArgs = commandArgs[1:]
		plan, err := a.load()
		if err != nil {
			return 0, err
		}
		opCtx, cancel := context.WithTimeout(ctx, a.timeout)
		values, err := engine.Resolve(opCtx, plan)
		cancel()
		if err != nil {
			if errors.Is(opCtx.Err(), context.DeadlineExceeded) {
				return 0, fmt.Errorf("operation timed out")
			}
			return 0, err
		}
		defer secret.DestroyMap(values)
		cmd := a.runtime.Command(ctx, commandArgs[0], commandArgs[1:]...)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = a.runtime.Stdin, a.runtime.Stdout, a.runtime.Stderr
		keys := secret.SortedKeys(values)
		cmd.Env = SafeChildEnvironment(a.runtime.Environ(), a.registry.CapabilityPrefixes(), keys)
		for _, key := range keys {
			cmd.Env = append(cmd.Env, key+"="+values[key].Reveal())
		}
		if err := cmd.Run(); err != nil {
			var exit *exec.ExitError
			if errors.As(err, &exit) {
				if code, ok := signalExitCode(exit.ProcessState); ok {
					return code, nil
				}
				return exit.ExitCode(), nil
			}
			return 0, fmt.Errorf("could not start child command")
		}
		return 0, nil
	case "rollback":
		fs := flag.NewFlagSet("rollback", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		force := fs.Bool("force", false, "roll back without an interactive confirmation")
		jsonOut := fs.Bool("json", false, "print machine-readable JSON output")
		if err := fs.Parse(commandArgs); err != nil {
			return 0, cleanFlagError(err)
		}
		if fs.NArg() != 0 {
			return 0, fmt.Errorf("rollback does not accept positional arguments")
		}
		plan, err := a.load()
		if err != nil {
			return 0, err
		}
		if !*force {
			ok, err := confirmAction(a.runtime, "rollback", fmt.Sprintf("This will roll back %d mapping(s) to their previous provider-side value.", len(plan.Mappings)))
			if err != nil {
				return 0, err
			}
			if !ok {
				return 0, fmt.Errorf("rollback aborted: not confirmed")
			}
		}
		opCtx, cancel := context.WithTimeout(ctx, a.timeout)
		defer cancel()
		results, err := engine.Rollback(opCtx, plan)
		if err == nil {
			if *jsonOut {
				err = printRollbackResultJSON(a.runtime.Stdout, results)
			} else {
				printRollbackResult(a.runtime.Stdout, results)
			}
			if err == nil {
				for _, result := range results {
					if result.Status == engine.Failed || result.Status == engine.Unsupported {
						err = fmt.Errorf("rollback incomplete")
						break
					}
				}
			}
		}
		if errors.Is(opCtx.Err(), context.DeadlineExceeded) {
			return 0, fmt.Errorf("operation timed out")
		}
		return 0, err
	default:
		return 0, fmt.Errorf("unknown command %q", command)
	}
}

func (a *app) load() (*engine.Plan, error) {
	path := a.templatePath
	if path == "" {
		path, _ = a.runtime.LookupEnv("UNO_TEMPLATE")
	}
	if path == "" {
		path = ".env.secrets-template"
	}
	data, err := a.runtime.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("could not read secrets template")
	}
	file, err := tpl.ParseEnv(string(data), a.runtime.LookupEnv)
	if err != nil {
		return nil, fmt.Errorf("template error: %w", err)
	}
	plan, err := engine.Bind(file, a.registry)
	if err != nil {
		return nil, fmt.Errorf("template error: %w", err)
	}
	return plan, nil
}

type invocation struct {
	command         string
	commandFound    bool
	globals         []string
	commandArgs     []string
	runHasSeparator bool
	// helpBeforeCommand and versionBeforeCommand record whether --help/-h or
	// --version were given ahead of the command name, as opposed to being
	// swept up from run's own (unseparated) arguments by name collision with
	// a global flag. Only the former is an unambiguous, explicit request.
	helpBeforeCommand    bool
	versionBeforeCommand bool
}

func parseInvocation(args []string, flags *flag.FlagSet) (invocation, error) {
	var parsed invocation
	globalOptionsEnded := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !parsed.commandFound {
			if !globalOptionsEnded && arg == "--" {
				globalOptionsEnded = true
				continue
			}
			if !globalOptionsEnded {
				if values, ok := globalFlagValues(flags, arg); ok {
					parsed.globals = append(parsed.globals, arg)
					switch flagName(arg) {
					case "help", "h":
						parsed.helpBeforeCommand = true
					case "version":
						parsed.versionBeforeCommand = true
					}
					if values == 1 {
						if i+1 >= len(args) {
							return invocation{}, parseFlagError(flags, arg)
						}
						i++
						parsed.globals = append(parsed.globals, args[i])
					}
					continue
				}
				if strings.HasPrefix(arg, "-") {
					return invocation{}, parseFlagError(flags, arg)
				}
			}
			parsed.command = arg
			parsed.commandFound = true
			continue
		}

		if arg == "--" {
			parsed.commandArgs = append(parsed.commandArgs, args[i:]...)
			parsed.runHasSeparator = parsed.command == "run"
			return parsed, nil
		}
		if values, ok := globalFlagValues(flags, arg); ok {
			parsed.globals = append(parsed.globals, arg)
			if values == 1 {
				if i+1 >= len(args) {
					return invocation{}, parseFlagError(flags, arg)
				}
				i++
				parsed.globals = append(parsed.globals, args[i])
			}
			continue
		}
		parsed.commandArgs = append(parsed.commandArgs, arg)
	}
	return parsed, nil
}

func flagName(arg string) string {
	name := strings.TrimPrefix(arg, "-")
	name = strings.TrimPrefix(name, "-")
	name, _, _ = strings.Cut(name, "=")
	return name
}

func globalFlagValues(flags *flag.FlagSet, arg string) (int, bool) {
	if len(arg) < 2 || arg[0] != '-' || arg == "--" {
		return 0, false
	}
	trimmed := strings.TrimPrefix(strings.TrimPrefix(arg, "-"), "-")
	name, _, hasValue := strings.Cut(trimmed, "=")
	registered := flags.Lookup(name)
	if registered == nil {
		return 0, false
	}
	if hasValue {
		return 0, true
	}
	if boolean, ok := registered.Value.(interface{ IsBoolFlag() bool }); ok && boolean.IsBoolFlag() {
		return 0, true
	}
	return 1, true
}

func parseFlagError(flags *flag.FlagSet, arg string) error {
	if err := flags.Parse([]string{arg}); err != nil {
		return cleanFlagError(err)
	}
	return fmt.Errorf("invalid arguments: invalid flag %s", arg)
}
func cleanFlagError(err error) error { return fmt.Errorf("invalid arguments: %w", err) }

// confirmAction asks for a yes/no answer on stdin/stdout before a
// destructive command proceeds. A non-interactive session (no TTY on
// stdin — the common case in CI) is refused outright with a message naming
// command, rather than hanging on a prompt nobody can answer.
func confirmAction(runtime Runtime, command, message string) (bool, error) {
	if !runtime.IsTerminal(runtime.Stdin) {
		return false, fmt.Errorf("%s requires --force to run non-interactively", command)
	}
	_, _ = fmt.Fprintln(runtime.Stdout, message)
	_, _ = fmt.Fprint(runtime.Stdout, "Proceed? [y/N] ")
	return readConfirmation(runtime.Stdin)
}

// confirmSync builds the confirmation callback SyncChanged invokes before
// writing any pending change. When force is set, nil is returned so
// SyncChanged writes unconditionally.
func confirmSync(runtime Runtime, force bool) func([]engine.Change) (bool, error) {
	if force {
		return nil
	}
	return func(pending []engine.Change) (bool, error) {
		var message strings.Builder
		fmt.Fprintf(&message, "%d pending change(s):", len(pending))
		for _, change := range pending {
			fmt.Fprintf(&message, "\n  %s: %s", change.Environment, change.Kind)
		}
		return confirmAction(runtime, "sync", message.String())
	}
}

func isInteractive(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func readConfirmation(in io.Reader) (bool, error) {
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && line == "" {
		return false, nil
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes", nil
}

// printSyncResult reports each written key exactly as before ("KEY: synced")
// so existing scripts parsing that line keep working, plus one additive
// summary line when any mapping's destination already matched (skipped, no
// write attempted, no needless secret-version churn).
func printSyncResult(out io.Writer, result engine.SyncResult, _ error) {
	completed := make(map[string]bool, len(result.Completed))
	for _, key := range result.Completed {
		completed[key] = true
	}
	for _, change := range result.Changes {
		if result.DryRun {
			_, _ = fmt.Fprintf(out, "[dry-run] %s: %s\n", change.Environment, change.Kind)
			continue
		}
		if change.Kind == engine.Unchanged {
			_, _ = fmt.Fprintf(out, "%s: unchanged\n", change.Environment)
			continue
		}
		if completed[change.Environment] {
			_, _ = fmt.Fprintf(out, "%s: %s\n", change.Environment, change.Kind)
		}
	}
}

type syncJSONResult struct {
	DryRun    bool            `json:"dryRun"`
	Changes   []engine.Change `json:"changes"`
	Completed []string        `json:"completed"`
	Error     string          `json:"error,omitempty"`
}

func printSyncResultJSON(writer io.Writer, result engine.SyncResult, err error) error {
	out := syncJSONResult{DryRun: result.DryRun, Changes: result.Changes, Completed: result.Completed}
	if err != nil {
		out.Error = err.Error()
	}
	return json.NewEncoder(writer).Encode(out)
}

func printRollbackResult(out io.Writer, results []engine.RollbackResult) {
	for _, result := range results {
		if result.Detail != "" {
			_, _ = fmt.Fprintf(out, "%s: %s (%s)\n", result.Environment, result.Status, result.Detail)
			continue
		}
		_, _ = fmt.Fprintf(out, "%s: %s\n", result.Environment, result.Status)
	}
}

type rollbackJSONResult struct {
	Results []engine.RollbackResult `json:"results"`
}

func printRollbackResultJSON(out io.Writer, results []engine.RollbackResult) error {
	return json.NewEncoder(out).Encode(rollbackJSONResult{Results: results})
}

func printHelp(out io.Writer) {
	_, _ = fmt.Fprint(out, `Bridge secrets through explicit source-to-destination mappings

Usage: uno [OPTIONS] <COMMAND>

Commands:
  check      Interpolate and validate mappings without provider access
  sync       Resolve every source, then write only changed destinations [--dry-run|--force|--json]
  dev        Resolve sources into a local .env.secrets file
  run        Resolve sources into a child process environment
  rollback   Revert each destination to its previous provider-side value [--force|--json]

Options:
  --template PATH   Secrets template path [env: UNO_TEMPLATE]
  --timeout DURATION  Provider operation timeout [default: 60s]
  --help            Print help
  --version         Print version
`)
}

func printCommandHelp(out io.Writer, command string) {
	switch command {
	case "check":
		_, _ = fmt.Fprint(out, "Usage: uno [OPTIONS] check\n\nValidate mappings without provider access.\n")
	case "sync":
		_, _ = fmt.Fprint(out, "Usage: uno [OPTIONS] sync [--dry-run] [--force] [--json]\n\nWrites only mappings whose destination would actually change.\n\nOptions:\n  --dry-run  Resolve sources and inspect destinations without writing\n  --force    Write pending changes without an interactive confirmation\n  --json     Print machine-readable JSON output\n")
	case "dev":
		_, _ = fmt.Fprint(out, "Usage: uno [OPTIONS] dev\n\nResolve sources into a local .env.secrets file.\n")
	case "run":
		_, _ = fmt.Fprint(out, "Usage: uno [OPTIONS] run -- <command> [args...]\n\nThe -- separator is required.\n")
	case "rollback":
		_, _ = fmt.Fprint(out, "Usage: uno [OPTIONS] rollback [--force] [--json]\n\nReverts each mapping's destination to its previous provider-side value.\nDestinations whose provider doesn't support rollback are reported, not attempted.\n\nOptions:\n  --force  Roll back without an interactive confirmation\n  --json   Print machine-readable JSON output\n")
	default:
		printHelp(out)
	}
}
