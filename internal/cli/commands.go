package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os/exec"

	"github.com/cntryl/uno/internal/core/engine"
	"github.com/cntryl/uno/internal/core/secret"
	"github.com/cntryl/uno/internal/devguard"
	"github.com/cntryl/uno/internal/dotenv"
)

func commandFlags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}
func rejectArgs(fs *flag.FlagSet, args []string, message string) error {
	if err := fs.Parse(args); err != nil {
		return cleanFlagError(err)
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("%s", message)
	}
	return nil
}
func (a *app) check(args []string) (int, error) {
	if err := rejectArgs(commandFlags("check"), args, "check does not accept arguments"); err != nil {
		return 0, err
	}
	plan, err := a.load()
	if err != nil {
		return 0, err
	}
	_, _ = fmt.Fprintf(a.runtime.Stdout, "template valid: %d mappings\n", len(plan.Mappings))
	return 0, nil
}
func (a *app) sync(ctx context.Context, args []string) (int, error) {
	fs := commandFlags("sync")
	dry := fs.Bool("dry-run", false, "")
	force := fs.Bool("force", false, "")
	jsonOut := fs.Bool("json", false, "")
	if err := rejectArgs(fs, args, "sync does not accept positional arguments"); err != nil {
		return 0, err
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
	return 0, wrapTimeout(opCtx, err)
}
func (a *app) dev(ctx context.Context, args []string) (int, error) {
	if err := rejectArgs(commandFlags("dev"), args, "dev does not accept arguments"); err != nil {
		return 0, err
	}
	plan, err := a.loadSources()
	if err != nil {
		return 0, err
	}
	if len(plan.Mappings) == 0 {
		_, _ = fmt.Fprintln(a.runtime.Stdout, "no mappings; left .env.secrets unchanged")
		return 0, nil
	}
	opCtx, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()
	if err := devguard.Check(opCtx, "."); err != nil {
		return 0, wrapTimeout(opCtx, err)
	}
	values, err := engine.Resolve(opCtx, plan)
	if err != nil {
		return 0, wrapTimeout(opCtx, err)
	}
	defer secret.DestroyMap(values)
	if err := devguard.Check(opCtx, "."); err != nil {
		return 0, wrapTimeout(opCtx, err)
	}
	if err := dotenv.Write(".env.secrets", values); err != nil {
		return 0, wrapTimeout(opCtx, err)
	}
	if err := wrapTimeout(opCtx, nil); err != nil {
		return 0, err
	}
	_, _ = fmt.Fprintf(a.runtime.Stdout, "wrote .env.secrets with %d secrets\n", len(values))
	return 0, nil
}
func (a *app) run(ctx context.Context, args []string) (int, error) {
	plan, err := a.loadSources()
	if err != nil {
		return 0, err
	}
	opCtx, cancel := context.WithTimeout(ctx, a.timeout)
	values, err := engine.Resolve(opCtx, plan)
	cancel()
	if err != nil {
		return 0, wrapTimeout(opCtx, err)
	}
	defer secret.DestroyMap(values)
	cmd := a.runtime.Command(ctx, args[0], args[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = a.runtime.Stdin, a.runtime.Stdout, a.runtime.Stderr
	keys := secret.SortedKeys(values)
	cmd.Env = SafeChildEnvironment(a.runtime.Environ(), a.registry.CapabilityPrefixes(), keys)
	for _, key := range keys {
		cmd.Env = append(cmd.Env, key+"="+values[key].Reveal())
	}
	if err := cmd.Run(); err != nil {
		return childExit(err)
	}
	return 0, nil
}
func childExit(err error) (int, error) {
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		return 0, fmt.Errorf("could not start child command")
	}
	if code, ok := signalExitCode(exit.ProcessState); ok {
		return code, nil
	}
	return exit.ExitCode(), nil
}
func (a *app) rollback(ctx context.Context, args []string) (int, error) {
	fs := commandFlags("rollback")
	force := fs.Bool("force", false, "")
	jsonOut := fs.Bool("json", false, "")
	if err := rejectArgs(fs, args, "rollback does not accept positional arguments"); err != nil {
		return 0, err
	}
	plan, err := a.load()
	if err != nil {
		return 0, err
	}
	if err = confirmRollback(a.runtime, plan, *force); err != nil {
		return 0, err
	}
	opCtx, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()
	results, err := engine.Rollback(opCtx, plan)
	if err == nil {
		err = outputRollback(a.runtime.Stdout, results, *jsonOut)
	}
	return 0, wrapTimeout(opCtx, err)
}
func confirmRollback(runtime Runtime, plan *engine.Plan, force bool) error {
	if force {
		return nil
	}
	ok, err := confirmAction(runtime, "rollback", fmt.Sprintf("This will roll back %d mapping(s) to their previous provider-side value.", len(plan.Mappings)))
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("rollback aborted: not confirmed")
	}
	return nil
}
func outputRollback(out io.Writer, results []engine.RollbackResult, jsonOut bool) error {
	if jsonOut {
		if err := printRollbackResultJSON(out, results); err != nil {
			return err
		}
	} else {
		printRollbackResult(out, results)
	}
	for _, result := range results {
		if result.Status == engine.Failed || result.Status == engine.Unsupported {
			return fmt.Errorf("rollback incomplete")
		}
	}
	return nil
}
