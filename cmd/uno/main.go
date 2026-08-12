package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	awsbridge "github.com/cntryl/uno/internal/aws"
	"github.com/cntryl/uno/internal/core/engine"
	"github.com/cntryl/uno/internal/core/provider"
	"github.com/cntryl/uno/internal/core/secret"
	tpl "github.com/cntryl/uno/internal/core/template"
	"github.com/cntryl/uno/internal/devguard"
	"github.com/cntryl/uno/internal/dotenv"
	opbridge "github.com/cntryl/uno/internal/onepassword"
)

const version = "0.1.0"

type app struct {
	templatePath string
	registry     *provider.Registry
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
	help, showVersion := false, false
	global.BoolVar(&help, "help", false, "show help")
	global.BoolVar(&help, "h", false, "show help")
	global.BoolVar(&showVersion, "version", false, "show version")
	commandAt := firstCommand(args)
	if commandAt < 0 {
		if err := global.Parse(args); err != nil {
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
	command := args[commandAt]
	globals, commandArgs, err := extractGlobalFlags(append(args[:commandAt], args[commandAt+1:]...), command == "run")
	if err != nil {
		return 0, err
	}
	if err := global.Parse(globals); err != nil {
		return 0, cleanFlagError(err)
	}
	if help || showVersion {
		if showVersion {
			fmt.Printf("uno %s\n", version)
		} else {
			printHelp()
		}
		return 0, nil
	}
	plan, err := a.load()
	if err != nil {
		return 0, err
	}
	switch command {
	case "check":
		if len(commandArgs) != 0 {
			return 0, fmt.Errorf("check does not accept arguments")
		}
		fmt.Printf("template valid: %d mappings\n", len(plan.Mappings))
		return 0, nil
	case "sync":
		fs := flag.NewFlagSet("sync", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		dry := fs.Bool("dry-run", false, "report mappings without provider access")
		if err := fs.Parse(commandArgs); err != nil {
			return 0, cleanFlagError(err)
		}
		if fs.NArg() != 0 {
			return 0, fmt.Errorf("sync does not accept positional arguments")
		}
		if *dry {
			for _, mapping := range plan.Mappings {
				fmt.Printf("%s: would sync\n", mapping.Environment)
			}
			return 0, nil
		}
		receipt, err := engine.Sync(ctx, plan)
		printReceipt(receipt, err)
		return 0, err
	case "dev":
		if len(commandArgs) != 0 {
			return 0, fmt.Errorf("dev does not accept arguments")
		}
		if err := devguard.Check(ctx, "."); err != nil {
			return 0, err
		}
		values, err := engine.Resolve(ctx, plan)
		if err != nil {
			return 0, err
		}
		defer destroyValues(values)
		if err := devguard.Check(ctx, "."); err != nil {
			return 0, err
		}
		if err := dotenv.Write(".env.secrets", values); err != nil {
			return 0, err
		}
		fmt.Printf("wrote .env.secrets with %d secrets\n", len(values))
		return 0, nil
	case "run":
		if len(commandArgs) > 0 && commandArgs[0] == "--" {
			commandArgs = commandArgs[1:]
		}
		if len(commandArgs) == 0 {
			return 0, fmt.Errorf("run requires a command after --")
		}
		values, err := engine.Resolve(ctx, plan)
		if err != nil {
			return 0, err
		}
		defer destroyValues(values)
		cmd := exec.CommandContext(ctx, commandArgs[0], commandArgs[1:]...)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
		cmd.Env = safeChildEnvironment(os.Environ())
		for _, key := range secret.SortedKeys(values) {
			cmd.Env = append(cmd.Env, key+"="+values[key].Reveal())
		}
		if err := cmd.Run(); err != nil {
			var exit *exec.ExitError
			if errors.As(err, &exit) {
				return exit.ExitCode(), nil
			}
			return 0, fmt.Errorf("could not start child command")
		}
		return 0, nil
	default:
		return 0, fmt.Errorf("unknown command %q", command)
	}
}

func destroyValues(values map[string]secret.Value) {
	for key, value := range values {
		value.Destroy()
		delete(values, key)
	}
}
func safeChildEnvironment(environment []string) []string {
	blocked := map[string]bool{"OP_SERVICE_ACCOUNT_TOKEN": true, "OP_ACCOUNT": true, "AWS_ACCESS_KEY_ID": true, "AWS_SECRET_ACCESS_KEY": true, "AWS_SESSION_TOKEN": true, "AWS_SECURITY_TOKEN": true, "AWS_PROFILE": true, "AWS_DEFAULT_PROFILE": true, "AWS_ROLE_ARN": true, "AWS_ROLE_SESSION_NAME": true, "AWS_WEB_IDENTITY_TOKEN_FILE": true, "AWS_SHARED_CREDENTIALS_FILE": true, "AWS_CONFIG_FILE": true, "AWS_SDK_LOAD_CONFIG": true, "AWS_CONTAINER_CREDENTIALS_FULL_URI": true, "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": true, "AWS_CONTAINER_AUTHORIZATION_TOKEN": true, "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE": true, "AWS_EC2_METADATA_SERVICE_ENDPOINT": true, "AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE": true}
	out := make([]string, 0, len(environment))
	for _, entry := range environment {
		key, _, ok := strings.Cut(entry, "=")
		if ok && !blocked[key] {
			out = append(out, entry)
		}
	}
	return out
}

func registry() *provider.Registry {
	r := provider.NewRegistry()
	opf := opbridge.Factory{}
	awsf := awsbridge.Factory{}
	r.Register("op", opf)
	r.Register("aws-secrets-manager", awsf)
	r.Register("aws-secrets-manager-arn", awsf)
	r.Register("aws-ssm", awsf)
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
func firstCommand(args []string) int {
	for i, arg := range args {
		if arg == "check" || arg == "sync" || arg == "dev" || arg == "run" {
			return i
		}
	}
	return -1
}
func extractGlobalFlags(args []string, run bool) ([]string, []string, error) {
	separator := len(args)
	if run {
		for i, arg := range args {
			if arg == "--" {
				separator = i
				break
			}
		}
	}
	before, after := args[:separator], args[separator:]
	globals, remaining := []string{}, []string{}
	for i := 0; i < len(before); i++ {
		arg := before[i]
		if arg == "--help" || arg == "-h" || arg == "--version" || strings.HasPrefix(arg, "--template=") {
			globals = append(globals, arg)
			continue
		}
		if arg == "--template" {
			if i+1 >= len(before) {
				return nil, nil, fmt.Errorf("invalid arguments: flag needs an argument: %s", arg)
			}
			globals = append(globals, arg, before[i+1])
			i++
			continue
		}
		remaining = append(remaining, arg)
	}
	return globals, append(remaining, after...), nil
}
func cleanFlagError(err error) error { return fmt.Errorf("invalid arguments: %w", err) }
func printReceipt(receipt engine.Receipt, err error) {
	completed := receipt.Completed
	var workflow *engine.Error
	if errors.As(err, &workflow) {
		completed = workflow.Completed
	}
	for _, key := range completed {
		fmt.Printf("%s: synced\n", key)
	}
}
func printHelp() {
	fmt.Print(`Bridge secrets through explicit source-to-destination mappings

Usage: uno [OPTIONS] <COMMAND>

Commands:
  check    Interpolate and validate mappings without provider access
  sync     Resolve every source, then write all destinations
  dev      Resolve sources into a local .env.secrets file
  run      Resolve sources into a child process environment

Options:
  --template PATH   Secrets template path [env: UNO_TEMPLATE]
  --help            Print help
  --version         Print version
`)
}
