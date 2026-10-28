package orchestrator

import (
	"context"
	"fmt"
	"io"
	"os/exec"
)

// Runner executes an external command, streaming its combined stdout+stderr to
// w. It is an interface so the orchestration flow can be driven by a fake in
// tests (no real processes) and by a dry-run implementation that only prints.
type Runner interface {
	Run(ctx context.Context, bin string, args []string, w io.Writer) error
}

// ExecRunner is the production Runner. It runs the real binary and streams all
// of its output live to w (typically a MultiWriter of the user's stderr and a
// run.log file), so long scans show progress instead of going silent.
type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, bin string, args []string, w io.Writer) error {
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdout = w
	cmd.Stderr = w
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting %s: %w", bin, err)
	}
	return cmd.Wait()
}

// CapturingRunner wraps a Runner but additionally tees the command's output
// into a buffer the caller provides, used for tools (assetfinder) that emit
// their results on stdout rather than to a file.
type CapturingRunner struct {
	Inner Runner
}

func (c CapturingRunner) RunCapture(ctx context.Context, bin string, args []string, live io.Writer, capture io.Writer) error {
	w := io.MultiWriter(live, capture)
	return c.Inner.Run(ctx, bin, args, w)
}
