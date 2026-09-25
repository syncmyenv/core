package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/syncmyenv/core/internal/config"
	"github.com/syncmyenv/core/internal/scanner"
)

func newScanCmd() *cobra.Command {
	var (
		asJSON    bool
		templates bool
		excludes  []string
	)
	cmd := &cobra.Command{
		Use:   "scan <dir> [dir...]",
		Short: "Discover env files under the given directories",
		Example: "  syncmyenv scan ~/Projects ~/Work\n" +
			"  syncmyenv scan ~/Projects --json",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			roots := make([]string, len(args))
			for i, a := range args {
				roots[i] = config.ExpandHome(a)
			}
			opt := scanner.Options{IncludeTemplate: templates}
			if len(excludes) > 0 {
				opt.Excludes = append(append([]string{}, scanner.DefaultExcludes...), excludes...)
			}
			res, err := scanner.Scan(roots, opt)
			if err != nil {
				return err
			}
			if asJSON {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(res)
			}
			if len(res) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "No environment files found.")
				return nil
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Found %d environment file(s)\n\n", len(res))
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "PROJECT\tFILE\tGIT")
			for _, r := range res {
				git := "-"
				if r.InGitRepo {
					git = "yes"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\n", r.ProjectName, r.Path, git)
			}
			return tw.Flush()
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "output JSON")
	cmd.Flags().BoolVar(&templates, "templates", false, "include .env.example and similar template files")
	cmd.Flags().StringSliceVar(&excludes, "exclude", nil, "extra directory names to skip")
	cmd.SetOut(os.Stdout)
	return cmd
}
