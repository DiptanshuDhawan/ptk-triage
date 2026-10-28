// ptk — recon triage CLI.
//
// Entry point. Delegates to the cobra command tree in internal cmd package.
package main

import (
	"fmt"
	"os"

	"ptk/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
