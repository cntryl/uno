package main

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

	awsbridge "github.com/cntryl/uno/internal/aws"
	azurebridge "github.com/cntryl/uno/internal/azure"
	"github.com/cntryl/uno/internal/core/engine"
	"github.com/cntryl/uno/internal/core/provider"
	"github.com/cntryl/uno/internal/core/secret"
	tpl "github.com/cntryl/uno/internal/core/template"
	"github.com/cntryl/uno/internal/devguard"
	"github.com/cntryl/uno/internal/dotenv"
	gcpbridge "github.com/cntryl/uno/internal/gcp"
	opbridge "github.com/cntryl/uno/internal/onepassword"
	vaultbridge "github.com/cntryl/uno/internal/vault"
)

const version = "0.1.1"

type app struct {
	templatePath string
	registry     *provider.Registry
	timeout      time.Duration
}

func main() {
	code, err := execute(context.Background(), os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	if code != 0 {
		os.Exit(code)
	}
}

func execute(ctx context.Context, args []string) (int, error) {
	return executeWithRegistry(ctx, args, registry())
}

func executeWithRegistry(ctx context.Context, args []string, providers *provider.Registry) (int, error) {
	a := &app{registry: providers}
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
			fmt.Printf("uno %s\n", version)
			return 0, nil
		}
		if help || len(args) == 0 {
			printHelp()
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
	// For "run", --help/--version short-circuit unless there's a leftover
	// positional argument suggesting the user forgot the "--" separator
	// (e.g. "run somecmd --version" should error, not print the version).
	// A flag given before the command name (helpBeforeCommand/
	// versionBeforeCommand) is always an explicit, unambiguous request and
	// wins regardless of what follows.
	if (help || showVersion) && (command != "run" || invocation.runHasSeparator || len(commandArgs) == 0 ||
		invocation.helpBeforeCommand || invocation.versionBeforeCommand) {
		if showVersion {
			fmt.Printf("uno %s\n", version)
		} else {
			printCommandHelp(command)
		}
		return 0, nil
	}
	if command == "run" && (!invocation.runHasSeparator || len(commandArgs) < 2 || commandArgs[0] != "--") {
		return 0, fmt.Errorf("run requires a command after --")
	}
	plan, err := a.load()
	if err != nil {
		return 0, err
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
		fmt.Printf("template valid: %d mappings\n", len(plan.Mappings))
		return 0, nil
	case "sync":
		fs := flag.NewFlagSet("sync", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		dry := fs.Bool("dry-run", false, "report mappings without provider access")
		force := fs.Bool("force", false, "write pending changes without an interactive confirmation")
		jsonOut := fs.Bool("json", false, "print machine-readable JSON output")
		if err := fs.Parse(commandArgs); err != nil {
			return 0, cleanFlagError(err)
		}
		if fs.NArg() != 0 {
			return 0, fmt.Errorf("sync does not accept positional arguments")
		}
		if *dry {
			return 0, printDryRun(plan, *jsonOut)
		}
		opCtx, cancel := context.WithTimeout(ctx, a.timeout)
		defer cancel()
		changes, receipt, err := engine.SyncChanged(opCtx, plan, confirmSync(*force))
		if *jsonOut {
			if jsonErr := printSyncResultJSON(changes, receipt, err); jsonErr != nil && err == nil {
				err = jsonErr
			}
		} else {
			printSyncResult(changes, receipt, err)
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
		fmt.Printf("wrote .env.secrets with %d secrets\n", len(values))
		return 0, nil
	case "run":
		commandArgs = commandArgs[1:]
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
		cmd := exec.CommandContext(ctx, commandArgs[0], commandArgs[1:]...)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
		cmd.Env = safeChildEnvironment(os.Environ(), a.registry.CapabilityPrefixes())
		for _, key := range secret.SortedKeys(values) {
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
		if !*force {
			ok, err := confirmAction("rollback", fmt.Sprintf("This will roll back %d mapping(s) to their previous provider-side value.", len(plan.Mappings)))
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
				err = printRollbackResultJSON(results)
			} else {
				printRollbackResult(results)
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

func registry() *provider.Registry {
	r := provider.NewRegistry()
	opf := opbridge.Factory{}
	awsf := awsbridge.Factory{}
	r.Register("op", opf)
	r.Register("aws-secrets-manager", awsf)
	r.Register("aws-secrets-manager-arn", awsf)
	r.Register("aws-ssm", awsf)
	r.Register("azure-key-vault", azurebridge.Factory{})
	r.Register("vault", vaultbridge.Factory{})
	r.Register("gcp-secret-manager", gcpbridge.Factory{})
	return r
}

func (a *app) load() (*engine.Plan, error) {
	path := a.templatePath
	if path == "" {
		path = os.Getenv("UNO_TEMPLATE")
	}
	if path == "" {
		path = ".env.secrets-template"
	}
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("could not read secrets template")
	}
	file, err := tpl.Parse(string(data))
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
func confirmAction(command, message string) (bool, error) {
	if !isInteractive(os.Stdin) {
		return false, fmt.Errorf("%s requires --force to run non-interactively", command)
	}
	fmt.Println(message)
	fmt.Print("Proceed? [y/N] ")
	return readConfirmation(os.Stdin)
}

// confirmSync builds the confirmation callback SyncChanged invokes before
// writing any pending change. When force is set, nil is returned so
// SyncChanged writes unconditionally.
func confirmSync(force bool) func([]engine.Change) (bool, error) {
	if force {
		return nil
	}
	return func(pending []engine.Change) (bool, error) {
		var message strings.Builder
		fmt.Fprintf(&message, "%d pending change(s):", len(pending))
		for _, change := range pending {
			fmt.Fprintf(&message, "\n  %s: %s", change.Environment, change.Kind)
		}
		return confirmAction("sync", message.String())
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

type dryRunJSONResult struct {
	DryRun   bool     `json:"dryRun"`
	Mappings []string `json:"mappings"`
}

func printDryRun(plan *engine.Plan, jsonOut bool) error {
	if jsonOut {
		environments := make([]string, 0, len(plan.Mappings))
		for _, mapping := range plan.Mappings {
			environments = append(environments, mapping.Environment)
		}
		return json.NewEncoder(os.Stdout).Encode(dryRunJSONResult{DryRun: true, Mappings: environments})
	}
	for _, mapping := range plan.Mappings {
		fmt.Printf("[dry-run] %s: would sync\n", mapping.Environment)
	}
	fmt.Printf("[dry-run] template valid: %d mappings; no providers contacted\n", len(plan.Mappings))
	return nil
}

func receiptCompleted(receipt engine.Receipt, err error) []string {
	completed := receipt.Completed
	var workflow *engine.Error
	if errors.As(err, &workflow) {
		completed = workflow.Completed
	}
	return completed
}

// printSyncResult reports each written key exactly as before ("KEY: synced")
// so existing scripts parsing that line keep working, plus one additive
// summary line when any mapping's destination already matched (skipped, no
// write attempted, no needless secret-version churn).
func printSyncResult(changes []engine.Change, receipt engine.Receipt, err error) {
	for _, key := range receiptCompleted(receipt, err) {
		fmt.Printf("%s: synced\n", key)
	}
	if unchanged := countUnchanged(changes); unchanged > 0 {
		fmt.Printf("%d unchanged, skipped\n", unchanged)
	}
}

type syncJSONResult struct {
	Changes   []engine.Change `json:"changes"`
	Completed []string        `json:"completed"`
	Unchanged int             `json:"unchanged"`
	Error     string          `json:"error,omitempty"`
}

func printSyncResultJSON(changes []engine.Change, receipt engine.Receipt, err error) error {
	out := syncJSONResult{Changes: changes, Completed: receiptCompleted(receipt, err), Unchanged: countUnchanged(changes)}
	if err != nil {
		out.Error = err.Error()
	}
	return json.NewEncoder(os.Stdout).Encode(out)
}

func countUnchanged(changes []engine.Change) int {
	unchanged := 0
	for _, change := range changes {
		if change.Kind == engine.Unchanged {
			unchanged++
		}
	}
	return unchanged
}

func printRollbackResult(results []engine.RollbackResult) {
	for _, result := range results {
		if result.Detail != "" {
			fmt.Printf("%s: %s (%s)\n", result.Environment, result.Status, result.Detail)
			continue
		}
		fmt.Printf("%s: %s\n", result.Environment, result.Status)
	}
}

type rollbackJSONResult struct {
	Results []engine.RollbackResult `json:"results"`
}

func printRollbackResultJSON(results []engine.RollbackResult) error {
	return json.NewEncoder(os.Stdout).Encode(rollbackJSONResult{Results: results})
}

func printHelp() {
	fmt.Print(`Bridge secrets through explicit source-to-destination mappings

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

func printCommandHelp(command string) {
	switch command {
	case "check":
		fmt.Print("Usage: uno [OPTIONS] check\n\nValidate mappings without provider access.\n")
	case "sync":
		fmt.Print("Usage: uno [OPTIONS] sync [--dry-run] [--force] [--json]\n\nWrites only mappings whose destination would actually change.\n\nOptions:\n  --dry-run  Preview mappings without provider access\n  --force    Write pending changes without an interactive confirmation\n  --json     Print machine-readable JSON output\n")
	case "dev":
		fmt.Print("Usage: uno [OPTIONS] dev\n\nResolve sources into a local .env.secrets file.\n")
	case "run":
		fmt.Print("Usage: uno [OPTIONS] run -- <command> [args...]\n\nThe -- separator is required.\n")
	case "rollback":
		fmt.Print("Usage: uno [OPTIONS] rollback [--force] [--json]\n\nReverts each mapping's destination to its previous provider-side value.\nDestinations whose provider doesn't support rollback are reported, not attempted.\n\nOptions:\n  --force  Roll back without an interactive confirmation\n  --json   Print machine-readable JSON output\n")
	default:
		printHelp()
	}
}
