package cli

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/syncmyenv/core/internal/daemon"
	"github.com/syncmyenv/core/internal/remote"
	"github.com/syncmyenv/core/internal/vault"
	"github.com/syncmyenv/core/internal/watcher"
)

func newDaemonCmd() *cobra.Command {
	var debounce time.Duration
	cmd := &cobra.Command{
		Use:   "daemon",
		Short: "Watch protected files and seal every change automatically",
		Long: `Run the background agent in the foreground. It watches every protected file
and seals a new revision whenever one changes. No password needed.

Most people want it to start on login instead:

  sme daemon install     # launchd (macOS) / systemd --user (Linux)
  sme daemon uninstall`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			lock, err := daemon.Acquire()
			if err != nil {
				return err
			}
			defer lock.Release()

			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			v, err := vault.Open(ctx)
			if err != nil {
				return err
			}
			defer v.Close()

			logger := log.New(cmd.OutOrStdout(), "", log.LstdFlags)
			pushNow := make(chan struct{}, 1)
			go pushLoop(ctx, v, logger, pushNow)
			w, err := watcher.New(v, watcher.Options{
				Debounce: debounce,
				OnSnapshot: func(r vault.SnapshotResult) {
					if r.Error != "" {
						logger.Printf("! %s — %s", tilde(r.Path), r.Error)
						return
					}
					logger.Printf("● %s → rev %d", tilde(r.Path), r.Seq)
					select {
					case pushNow <- struct{}{}:
					default:
					}
				},
				OnError: func(err error) { logger.Printf("! %v", err) },
			})
			if err != nil {
				return err
			}
			files, _ := v.List(ctx)
			logger.Printf("syncmyenv daemon started · watching %d file(s)", len(files))
			err = w.Run(ctx)
			logger.Printf("syncmyenv daemon stopped")
			if errors.Is(err, context.Canceled) {
				return nil
			}
			return err
		},
	}
	cmd.Flags().DurationVar(&debounce, "debounce", 500*time.Millisecond, "wait this long after the last change before sealing")

	var printOnly bool
	install := &cobra.Command{
		Use:   "install",
		Short: "Start the daemon on login (launchd / systemd --user)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := vault.LoadKeyFile(); err != nil {
				return err
			}
			s, err := daemon.NewService()
			if err != nil {
				return err
			}
			if printOnly {
				body, err := s.Render()
				if err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "# %s\n%s", s.Path, body)
				return nil
			}
			if err := s.Install(); err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "✓ daemon installed and started\n")
			fmt.Fprintf(w, "  service  %s\n", tilde(s.Path))
			fmt.Fprintf(w, "  binary   %s\n", tilde(s.Exe))
			fmt.Fprintf(w, "  log      %s\n", tilde(s.LogPath))
			fmt.Fprintln(w, "  note     if you move the binary, run `sme daemon install` again")
			return nil
		},
	}
	install.Flags().BoolVar(&printOnly, "print", false, "print the service file instead of installing it")

	uninstall := &cobra.Command{
		Use:   "uninstall",
		Short: "Stop the daemon and remove it from login",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, err := daemon.NewService()
			if err != nil {
				return err
			}
			if err := s.Uninstall(); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "✓ daemon stopped and uninstalled (your vault is untouched)")
			return nil
		},
	}
	cmd.AddCommand(install, uninstall)
	return cmd
}

// daemonStatus is one line for `sme status`.
func daemonStatus() string {
	if ok, pid := daemon.Running(); ok {
		if pid > 0 {
			return fmt.Sprintf("✓ running (pid %d)", pid)
		}
		return "✓ running"
	}
	if s, err := daemon.NewService(); err == nil && s.Installed() {
		return "installed but not running — check " + tilde(s.LogPath)
	}
	return "not running — `sme daemon install` to version changes automatically"
}

// pushLoop uploads new revisions when the watcher seals one, and every 30s
// (retrying after network errors). Password-free: needs only the device
// token, device signing key and the vault's public recipient.
func pushLoop(ctx context.Context, v *vault.Vault, logger *log.Logger, trigger <-chan struct{}) {
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	lastErr := ""
	for {
		cfg, err := remote.Load()
		if err == nil && cfg.VaultID != "" {
			s := &remote.Syncer{V: v, Cfg: cfg, Client: cfg.Client(version)}
			n, err := s.Push(ctx)
			switch {
			case err != nil && err.Error() != lastErr:
				logger.Printf("! push: %v", err)
				lastErr = err.Error()
			case err == nil && n > 0:
				logger.Printf("↑ pushed %d revision(s) to %s", n, cfg.Server)
				lastErr = ""
			case err == nil:
				lastErr = ""
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-trigger:
		case <-tick.C:
		}
	}
}
