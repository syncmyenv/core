// Package cli wires the syncmyenv command tree.
package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Set at build time: -ldflags "-X github.com/syncmyenv/core/internal/cli.version=v0.1.0"
var (
	version = "dev"
	commit  = "none"
)

func newRoot() *cobra.Command {
	root := &cobra.Command{
		Use:           "syncmyenv",
		Short:         "Local-first, encrypted backup and sync for your .env files",
		SilenceUsage:  true,
		SilenceErrors: false,
		Version:       fmt.Sprintf("%s (%s)", version, commit),
	}
	root.AddCommand(
		newScanCmd(),
		newInitCmd(),
		newStatusCmd(),
		newKeysCmd(),
		newProtectCmd(),
		newUnprotectCmd(),
		newListCmd(),
		newSnapshotCmd(),
		newHistoryCmd(),
		newRestoreCmd(),
		newDaemonCmd(),
		stub("sync", "Sync encrypted revisions with remote storage", 2),
		stub("share <file>", "Create a temporary encrypted share", 4),
	)
	return root
}

// Execute runs the CLI.
func Execute() error { return newRoot().Execute() }

func stub(use, short string, phase int) *cobra.Command {
	return &cobra.Command{
		Use:   use,
		Short: short,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return fmt.Errorf("%s: not implemented yet (planned for phase %d)", cmd.Name(), phase)
		},
	}
}
