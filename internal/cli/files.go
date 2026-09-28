package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"github.com/syncmyenv/core/internal/config"
	"github.com/syncmyenv/core/internal/crypto"
	"github.com/syncmyenv/core/internal/scanner"
	"github.com/syncmyenv/core/internal/vault"
	"golang.org/x/term"
)

func newProtectCmd() *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:   "protect <file|dir>...",
		Short: "Start protecting env files (seals their current contents)",
		Long: `Protect env files: their current contents are sealed into the vault as
revision 1, and later changes become new revisions (sme snapshot / sme daemon).

Pass files directly, or directories to scan them and choose what to protect.
No password needed — sealing only uses the vault's public key.`,
		Example: "  sme protect .env .env.local\n  sme protect ~/Projects --yes",
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			w := cmd.OutOrStdout()
			var files, dirs []string
			for _, a := range args {
				p := config.ExpandHome(a)
				st, err := os.Stat(p)
				if err != nil {
					return err
				}
				if st.IsDir() {
					dirs = append(dirs, p)
				} else {
					files = append(files, p)
				}
			}
			if len(dirs) > 0 {
				found, err := scanner.Scan(dirs, scanner.Options{})
				if err != nil {
					return err
				}
				if len(found) == 0 && len(files) == 0 {
					fmt.Fprintln(w, "No environment files found.")
					return nil
				}
				fmt.Fprintf(w, "Found %d environment file(s):\n", len(found))
				for _, f := range found {
					fmt.Fprintf(w, "  %s\n", tilde(f.Path))
					files = append(files, f.Path)
				}
				if !yes {
					ok, err := confirm(cmd, fmt.Sprintf("Protect these %d file(s)?", len(found)))
					if err != nil {
						return err
					}
					if !ok {
						fmt.Fprintln(w, "Nothing protected.")
						return nil
					}
				}
			}
			v, err := vault.Open(cmd.Context())
			if err != nil {
				return err
			}
			defer v.Close()
			res, err := v.Protect(cmd.Context(), files)
			if err != nil {
				return err
			}
			added := 0
			for _, r := range res {
				switch {
				case r.Skipped != "":
					fmt.Fprintf(w, "  ! %s — skipped: %s\n", tilde(r.Path), r.Skipped)
				case r.Added:
					added++
					fmt.Fprintf(w, "  + %s\n", tilde(r.Path))
				default:
					fmt.Fprintf(w, "  = %s (already protected)\n", tilde(r.Path))
				}
			}
			fmt.Fprintf(w, "✓ %d file(s) protected · contents sealed to vault %s\n", added, crypto.Fingerprint(v.KeyFile().Recipient))
			return nil
		},
	}
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "don't ask for confirmation when scanning directories")
	return cmd
}

func newUnprotectCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "unprotect <file>...",
		Short: "Stop protecting files (history is kept and still restorable)",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			v, err := vault.Open(cmd.Context())
			if err != nil {
				return err
			}
			defer v.Close()
			for _, a := range args {
				if err := v.Unprotect(cmd.Context(), config.ExpandHome(a)); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "  - %s\n", tilde(a))
			}
			return nil
		},
	}
}

func newListCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List protected files",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			v, err := vault.Open(cmd.Context())
			if err != nil {
				return err
			}
			defer v.Close()
			files, err := v.List(cmd.Context())
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			if asJSON {
				type row struct {
					Path       string    `json:"path"`
					Project    string    `json:"project"`
					Revisions  int       `json:"revisions"`
					LastChange time.Time `json:"last_change"`
				}
				rows := []row{}
				for _, f := range files {
					rows = append(rows, row{f.Path, f.Project, f.Revisions, f.LastChange})
				}
				enc := json.NewEncoder(w)
				enc.SetIndent("", "  ")
				return enc.Encode(rows)
			}
			if len(files) == 0 {
				fmt.Fprintln(w, "No protected files. Try: sme protect ~/Projects")
				return nil
			}
			tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "PROJECT\tFILE\tREVS\tLAST CHANGE")
			for _, f := range files {
				fmt.Fprintf(tw, "%s\t%s\t%d\t%s\n", f.Project, tilde(f.Path), f.Revisions, ago(f.LastChange))
			}
			return tw.Flush()
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "output JSON")
	return cmd
}

func newSnapshotCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "snapshot",
		Short: "Seal a new revision of every protected file that changed",
		Long: `Check every protected file and seal a new revision for each one that changed.
The daemon does this automatically; run it by hand any time. No password needed.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			v, err := vault.Open(cmd.Context())
			if err != nil {
				return err
			}
			defer v.Close()
			res, err := v.Snapshot(cmd.Context())
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			changed, unchanged := 0, 0
			for _, r := range res {
				switch {
				case r.Missing:
					fmt.Fprintf(w, "  ! %s — missing on disk (sme restore %s)\n", tilde(r.Path), tilde(r.Path))
				case r.Error != "":
					fmt.Fprintf(w, "  ! %s — %s\n", tilde(r.Path), r.Error)
				case r.Seq > 0:
					changed++
					fmt.Fprintf(w, "  ↑ %s → rev %d\n", tilde(r.Path), r.Seq)
				default:
					unchanged++
				}
			}
			fmt.Fprintf(w, "✓ %d changed, %d unchanged\n", changed, unchanged)
			return nil
		},
	}
}

func newHistoryCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "history <file>",
		Short: "Show revisions of a protected file (values stay sealed)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			v, err := vault.Open(cmd.Context())
			if err != nil {
				return err
			}
			defer v.Close()
			revs, err := v.History(cmd.Context(), config.ExpandHome(args[0]))
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			abs, _ := vault.CleanPath(config.ExpandHome(args[0]))
			fmt.Fprintf(w, "%s\n\n", tilde(abs))
			tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "REV\tWHEN\tSIZE\tSOURCE\tDEVICE")
			for _, r := range revs {
				fmt.Fprintf(tw, "%d\t%s\t%dB\t%s\t%s\n", r.Seq, r.CreatedAt.Local().Format("2006-01-02 15:04:05"), r.Size, r.Source, r.Device)
			}
			if err := tw.Flush(); err != nil {
				return err
			}
			fmt.Fprintf(w, "\nrestore one: sme restore %s --version <rev>\n", tilde(abs))
			return nil
		},
	}
}

func newRestoreCmd() *cobra.Command {
	var (
		version            int
		to                 string
		missing, fromStdin bool
		useRecovery        bool
	)
	cmd := &cobra.Command{
		Use:   "restore [file]",
		Short: "Restore a file (or all missing files) from the vault",
		Long: `Decrypt a revision and write it back to disk. Whatever is on disk now is
snapshotted first, so a restore never loses data. Needs your master password.`,
		Example: "  sme restore .env                 # latest revision\n" +
			"  sme restore .env --version 3\n" +
			"  sme restore .env --to /tmp/old.env\n" +
			"  sme restore --missing            # everything deleted / new machine",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if missing == (len(args) == 1) {
				return errors.New("pass a file, or --missing")
			}
			v, err := vault.Open(cmd.Context())
			if err != nil {
				return err
			}
			defer v.Close()
			w := cmd.OutOrStdout()

			var targets []string
			if missing {
				fs, err := v.Missing(cmd.Context())
				if err != nil {
					return err
				}
				if len(fs) == 0 {
					fmt.Fprintln(w, "✓ nothing missing")
					return nil
				}
				for _, f := range fs {
					targets = append(targets, f.Path)
				}
			} else {
				targets = []string{config.ExpandHome(args[0])}
			}

			key, err := unlock(cmd, v.KeyFile(), newPrompter(cmd, fromStdin), useRecovery)
			if err != nil {
				return err
			}
			for _, t := range targets {
				r, err := v.Restore(cmd.Context(), key, t, version, config.ExpandHome(to))
				if err != nil {
					return err
				}
				switch {
				case r.Unchanged:
					fmt.Fprintf(w, "= %s already matches rev %d\n", tilde(r.Path), r.FromSeq)
				case to != "":
					fmt.Fprintf(w, "✓ wrote rev %d to %s\n", r.FromSeq, tilde(r.Path))
				case r.SavedSeq > 0:
					fmt.Fprintf(w, "✓ restored %s from rev %d (previous content saved as rev %d)\n", tilde(r.Path), r.FromSeq, r.SavedSeq)
				default:
					fmt.Fprintf(w, "✓ restored %s from rev %d\n", tilde(r.Path), r.FromSeq)
				}
			}
			return nil
		},
	}
	cmd.Flags().IntVar(&version, "version", 0, "revision to restore (default: latest)")
	cmd.Flags().StringVar(&to, "to", "", "write to this path instead of the original")
	cmd.Flags().BoolVar(&missing, "missing", false, "restore every protected file that's missing on disk")
	cmd.Flags().BoolVar(&fromStdin, "password-stdin", false, "read secrets from stdin (one per line)")
	cmd.Flags().BoolVar(&useRecovery, "recovery", false, "unlock with the recovery key")
	return cmd
}

// ---- helpers ----

func confirm(cmd *cobra.Command, q string) (bool, error) {
	f, ok := cmd.InOrStdin().(*os.File)
	if !ok || !term.IsTerminal(int(f.Fd())) {
		return false, errors.New("not a terminal — pass --yes to confirm")
	}
	fmt.Fprintf(cmd.OutOrStdout(), "%s [y/N] ", q)
	var ans string
	_, _ = fmt.Fscanln(f, &ans)
	ans = strings.ToLower(strings.TrimSpace(ans))
	return ans == "y" || ans == "yes", nil
}

func tilde(p string) string {
	home, err := os.UserHomeDir()
	if err == nil && (p == home || strings.HasPrefix(p, home+string(filepath.Separator))) {
		return "~" + p[len(home):]
	}
	return p
}

func ago(t time.Time) string {
	if t.Unix() <= 0 {
		return "—"
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}
