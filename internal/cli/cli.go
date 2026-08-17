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
	tpl "github.com/cntryl/uno/internal/core/template"
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
	defer func() { code = classifyExit(code, err) }()
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
		return 0, handleNoCommand(a, global, invocation, len(args), &help, &showVersion)
	}
	command, commandArgs := invocation.command, invocation.commandArgs
	if err := global.Parse(invocation.globals); err != nil {
		return 0, cleanFlagError(err)
	}
	if err := validateCommand(command, a.timeout); err != nil {
		return 0, err
	}
	// For "run", --help/--version short-circuit unless there's a leftover
	// positional argument suggesting the user forgot the "--" separator
	// (e.g. "run somecmd --version" should error, not print the version).
	// A flag given before the command name (helpBeforeCommand/
	// versionBeforeCommand) is always an explicit, unambiguous request and
	// wins regardless of what follows.
	if shouldShortCircuit(invocation, help, showVersion) {
		if showVersion {
			_, _ = fmt.Fprintf(a.runtime.Stdout, "uno %s\n", version)
		} else {
			printCommandHelp(a.runtime.Stdout, command)
		}
		return 0, nil
	}
	if err := validateRunInvocation(invocation); err != nil {
		return 0, err
	}
	return a.dispatch(ctx, command, commandArgs)
}
func validateRunInvocation(in invocation) error {
	if in.command != "run" {
		return nil
	}
	if !in.runHasSeparator || len(in.commandArgs) < 2 || in.commandArgs[0] != "--" {
		return fmt.Errorf("run requires a command after --")
	}
	return nil
}

func validateCommand(command string, timeout time.Duration) error {
	if timeout <= 0 {
		return fmt.Errorf("invalid arguments: timeout must be greater than zero")
	}
	switch command {
	case "check", "sync", "dev", "run", "rollback":
		return nil
	default:
		return fmt.Errorf("unknown command %q", command)
	}
}
func shouldShortCircuit(in invocation, help, version bool) bool {
	return (help || version) && (in.command != "run" || in.runHasSeparator || len(in.commandArgs) == 0 || in.helpBeforeCommand || in.versionBeforeCommand)
}

func classifyExit(code int, err error) int {
	if err == nil {
		return code
	}
	for _, marker := range []string{"invalid arguments:", "unknown command ", "a command is required", " does not accept ", "run requires a command"} {
		if strings.Contains(err.Error(), marker) {
			return 2
		}
	}
	return 1
}
func handleNoCommand(a *app, global *flag.FlagSet, in invocation, argCount int, help, showVersion *bool) error {
	if err := global.Parse(in.globals); err != nil {
		return cleanFlagError(err)
	}
	if *showVersion {
		_, _ = fmt.Fprintf(a.runtime.Stdout, "uno %s\n", version)
		return nil
	}
	if *help || argCount == 0 {
		printHelp(a.runtime.Stdout)
		return nil
	}
	return fmt.Errorf("a command is required")
}
func (a *app) dispatch(ctx context.Context, command string, args []string) (int, error) {
	switch command {
	case "check":
		return a.check(args)
	case "sync":
		return a.sync(ctx, args)
	case "dev":
		return a.dev(ctx, args)
	case "run":
		return a.run(ctx, args[1:])
	case "rollback":
		return a.rollback(ctx, args)
	default:
		return 0, fmt.Errorf("unknown command %q", command)
	}
}

func (a *app) load() (*engine.Plan, error) {
	return a.loadWith(tpl.ParseEnv, engine.Bind)
}

func (a *app) loadSources() (*engine.Plan, error) {
	return a.loadWith(tpl.ParseSourcesEnv, engine.BindSources)
}

func (a *app) loadWith(
	parse func(string, func(string) (string, bool)) (*tpl.File, error),
	bind func(*tpl.File, *provider.Registry) (*engine.Plan, error),
) (*engine.Plan, error) {
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
	file, err := parse(string(data), a.runtime.LookupEnv)
	if err != nil {
		return nil, fmt.Errorf("template error: %w", err)
	}
	plan, err := bind(file, a.registry)
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
	for i := 0; i < len(args); {
		if !parsed.commandFound {
			_, ended, err := parseBeforeCommand(&parsed, args, &i, flags, globalOptionsEnded)
			if err != nil {
				return invocation{}, err
			}
			globalOptionsEnded = ended
			i++
			continue
		}
		done, err := parseAfterCommand(&parsed, args, &i, flags)
		if err != nil {
			return invocation{}, err
		}
		if done {
			return parsed, nil
		}
		i++
	}
	return parsed, nil
}

func parseBeforeCommand(parsed *invocation, args []string, index *int, flags *flag.FlagSet, ended bool) (bool, bool, error) {
	arg := args[*index]
	if !ended && arg == "--" {
		return true, true, nil
	}
	if !ended && strings.HasPrefix(arg, "-") {
		return parsePreCommandFlag(parsed, args, index, flags, ended, arg)
	}
	parsed.command = arg
	parsed.commandFound = true
	return true, ended, nil
}
func parsePreCommandFlag(parsed *invocation, args []string, index *int, flags *flag.FlagSet, ended bool, arg string) (bool, bool, error) {
	values, ok := globalFlagValues(flags, arg)
	if !ok {
		return false, ended, parseFlagError(flags, arg)
	}
	parsed.globals = append(parsed.globals, arg)
	markPreCommandFlag(parsed, arg)
	if values == 0 {
		return true, ended, nil
	}
	if *index+1 >= len(args) {
		return false, ended, parseFlagError(flags, arg)
	}
	*index++
	parsed.globals = append(parsed.globals, args[*index])
	return true, ended, nil
}
func markPreCommandFlag(parsed *invocation, arg string) {
	switch flagName(arg) {
	case "help", "h":
		parsed.helpBeforeCommand = true
	case "version":
		parsed.versionBeforeCommand = true
	}
}
func parseAfterCommand(parsed *invocation, args []string, index *int, flags *flag.FlagSet) (bool, error) {
	arg := args[*index]
	if arg == "--" {
		parsed.commandArgs = append(parsed.commandArgs, args[*index:]...)
		parsed.runHasSeparator = parsed.command == "run"
		return true, nil
	}
	if values, ok := globalFlagValues(flags, arg); ok {
		parsed.globals = append(parsed.globals, arg)
		if values == 1 {
			if *index+1 >= len(args) {
				return false, parseFlagError(flags, arg)
			}
			*index++
			parsed.globals = append(parsed.globals, args[*index])
		}
		return false, nil
	}
	parsed.commandArgs = append(parsed.commandArgs, arg)
	return false, nil
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

// wrapTimeout reports a plain "operation timed out" instead of err when
// ctx's own deadline is why the preceding call failed — the provider error
// it would otherwise return (e.g. "read failed: Indeterminate") is
// misleading when the real cause was simply running out of time. Passing a
// nil err still surfaces the timeout if the deadline was reached exactly as
// the last operation finished successfully.
func wrapTimeout(ctx context.Context, err error) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("operation timed out")
	}
	return err
}

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
