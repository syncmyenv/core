package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/spf13/cobra"
	"github.com/syncmyenv/core/internal/crypto"
	"github.com/syncmyenv/core/internal/remote"
	"github.com/syncmyenv/core/internal/vault"
	"github.com/syncmyenv/core/protocol"
)

func newLoginCmd() *cobra.Command {
	var name string
	var noBrowser bool
	cmd := &cobra.Command{
		Use:   "login [server]",
		Short: "Link this device to SyncMyEnv Cloud or your self-hosted server",
		Long: `Link this device to a server using a one-time code you approve in the
browser (OAuth device flow). The server only ever receives ciphertext.

  sme login                           # SyncMyEnv Cloud (cloud.syncmyenv.com)
  sme login env.mycompany.com         # your self-hosted server (https implied)
  sme login http://192.168.1.20:8080  # plain http only for localhost / LAN

Set SYNCMYENV_SERVER to change the default for everyone on a machine.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			server := remote.DefaultServer
			if env := os.Getenv("SYNCMYENV_SERVER"); env != "" {
				server = env
			}
			if len(args) == 1 {
				server = args[0]
			}
			server, err := protocol.ValidateURL(server)
			if err != nil {
				return err
			}
			if name == "" {
				name, _ = os.Hostname()
			}
			w := cmd.OutOrStdout()
			c := &protocol.Client{BaseURL: server, UA: "syncmyenv-cli/" + version}
			dc, err := c.DeviceCode(cmd.Context(), name)
			if err != nil {
				return fmt.Errorf("contacting %s: %w", server, err)
			}
			fmt.Fprintf(w, "To link this device, open:\n\n    %s\n\nand check it shows this code:  %s\n\n", dc.VerificationURIComplete, dc.UserCode)
			if !noBrowser && openBrowser(dc.VerificationURIComplete) {
				fmt.Fprintln(w, "(opened your browser)")
			}
			fmt.Fprintln(w, "waiting for approval… (Ctrl-C to cancel)")

			tok, err := pollDeviceToken(cmd.Context(), c, dc)
			if err != nil {
				return err
			}
			c.Token = tok.AccessToken
			me, err := c.Me(cmd.Context())
			if err != nil {
				return err
			}
			cfg := &remote.Config{Server: server, Token: tok.AccessToken, DeviceID: tok.Device.ID, DeviceName: tok.Device.Name, Email: me.User.Email}
			if err := cfg.Save(); err != nil {
				return err
			}
			fmt.Fprintf(w, "✓ logged in to %s as %s (device %q)\n", server, me.User.Email, tok.Device.Name)
			fmt.Fprintln(w, "  next: sme sync")
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "device name shown in the dashboard (default: hostname)")
	cmd.Flags().BoolVar(&noBrowser, "no-browser", false, "don't try to open a browser")
	return cmd
}

func pollDeviceToken(ctx context.Context, c *protocol.Client, dc *protocol.DeviceCodeResponse) (*protocol.DeviceTokenResponse, error) {
	interval := time.Duration(max(dc.Interval, 1)) * time.Second
	deadline := time.Now().Add(time.Duration(dc.ExpiresIn) * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(interval):
		}
		tok, err := c.DeviceToken(ctx, dc.DeviceCode)
		if err == nil {
			return tok, nil
		}
		var apiErr *protocol.APIError
		if !errors.As(err, &apiErr) {
			return nil, err
		}
		switch apiErr.Code {
		case "authorization_pending":
		case "slow_down":
			interval += 5 * time.Second
		case "access_denied":
			return nil, errors.New("login was denied in the browser")
		case "expired_token":
			return nil, errors.New("code expired — run `sme login` again")
		default:
			return nil, err
		}
	}
	return nil, errors.New("code expired — run `sme login` again")
}

func openBrowser(url string) bool {
	if os.Getenv("SSH_CONNECTION") != "" {
		return false
	}
	var c *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		c = exec.Command("open", url)
	case "linux":
		c = exec.Command("xdg-open", url)
	default:
		return false
	}
	return c.Start() == nil
}

func newLogoutCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Unlink this device from the server (local vault is untouched)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := remote.Load()
			if errors.Is(err, remote.ErrNotLoggedIn) {
				fmt.Fprintln(cmd.OutOrStdout(), "not logged in")
				return nil
			} else if err != nil {
				return err
			}
			if err := cfg.Client(version).RevokeSelf(cmd.Context()); err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "warning: couldn't revoke the token on the server (%v) — revoke %q from the dashboard\n", err, cfg.DeviceName)
			}
			if err := remote.Delete(); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "✓ logged out of %s\n", cfg.Server)
			return nil
		},
	}
}

func newSyncCmd() *cobra.Command {
	var fromStdin, useRecovery, pushOnly bool
	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Push this device's revisions and pull other devices' changes",
		Long: `Sync with the server you logged in to.

  push   upload new sealed revisions (no password needed; the daemon does this)
  pull   verify + import other devices' revisions. Needs your master password,
         since checking and decrypting them requires the vault key.

On a new machine, sync also downloads your (still encrypted) vault key file,
then 'sme restore --missing' brings your env files back.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			w := cmd.OutOrStdout()
			cfg, err := remote.Load()
			if err != nil {
				return err
			}
			client := cfg.Client(version)

			// New machine: fetch the wrapped vault key from the server.
			if _, err := vault.LoadKeyFile(); errors.Is(err, vault.ErrNotInitialized) {
				kf, err := remote.FetchKeyring(ctx, cfg, client, "")
				if err != nil {
					return err
				}
				if err := vault.CreateKeyFile(kf); err != nil {
					return err
				}
				fmt.Fprintf(w, "✓ fetched vault %s from %s (still encrypted)\n", crypto.Fingerprint(kf.Recipient), cfg.Server)
			} else if err != nil {
				return err
			}

			v, err := vault.Open(ctx)
			if err != nil {
				return err
			}
			defer v.Close()
			s := &remote.Syncer{V: v, Cfg: cfg, Client: client}
			created, err := s.EnsureVault(ctx)
			if err != nil {
				return err
			}
			if created {
				fmt.Fprintf(w, "✓ created vault %s on %s\n", crypto.Fingerprint(v.KeyFile().Recipient), cfg.Server)
			}

			var incoming []protocol.StoredEntry
			var cursor int64
			if !pushOnly {
				if incoming, cursor, err = s.Incoming(ctx); err != nil {
					return err
				}
			}

			// Unlock only when needed: first-time device authorization, or pulling.
			var key *crypto.VaultKey
			if !s.Authorized(ctx) || len(incoming) > 0 {
				if len(incoming) > 0 {
					fmt.Fprintf(w, "%d change(s) from other devices — unlock to verify & import\n", len(incoming))
				} else {
					fmt.Fprintln(w, "authorizing this device (one time) — unlock your vault")
				}
				if key, err = unlock(cmd, v.KeyFile(), newPrompter(cmd, fromStdin), useRecovery); err != nil {
					return err
				}
			}
			if !s.Authorized(ctx) {
				if err := s.Authorize(ctx, key); err != nil {
					return err
				}
				fmt.Fprintln(w, "✓ device authorized — future pushes need no password")
			}

			n, err := s.Push(ctx)
			if err != nil {
				return err
			}
			if n > 0 {
				fmt.Fprintf(w, "↑ pushed %d revision(s)\n", n)
			}

			if len(incoming) > 0 {
				res, err := s.Pull(ctx, key, incoming, cursor)
				if err != nil {
					return err
				}
				for _, r := range res.Imported {
					switch {
					case r.Applied:
						fmt.Fprintf(w, "↓ %s → rev %d (updated on disk)\n", tilde(r.Path), r.Seq)
					case r.Conflict:
						fmt.Fprintf(w, "↓ %s → rev %d (kept your local edits; remote version is in history)\n", tilde(r.Path), r.Seq)
					case r.OnlyStore:
						fmt.Fprintf(w, "↓ %s → rev %d (not on disk — sme restore --missing)\n", tilde(r.Path), r.Seq)
					default:
						fmt.Fprintf(w, "↓ %s → rev %d\n", tilde(r.Path), r.Seq)
					}
				}
				if res.Rejected > 0 {
					fmt.Fprintf(w, "! rejected %d entr(y/ies) that failed verification (not signed by a device of this vault)\n", res.Rejected)
				}
			} else if !pushOnly {
				_ = v.SetState(ctx, "pull_cursor", fmt.Sprint(cursor))
			}
			fmt.Fprintf(w, "✓ in sync with %s\n", cfg.Server)
			return nil
		},
	}
	cmd.Flags().BoolVar(&fromStdin, "password-stdin", false, "read secrets from stdin (one per line)")
	cmd.Flags().BoolVar(&useRecovery, "recovery", false, "unlock with the recovery key")
	cmd.Flags().BoolVar(&pushOnly, "push-only", false, "only upload; don't pull (never asks for a password once authorized)")
	return cmd
}

// remoteStatus is one line for `sme status`.
func remoteStatus(ctx context.Context, v *vault.Vault) string {
	cfg, err := remote.Load()
	if err != nil {
		return "local only — `sme login` to sync with SyncMyEnv Cloud or your own server"
	}
	pending, _ := v.CountPending(ctx)
	s := fmt.Sprintf("%s as %s", cfg.Server, cfg.Email)
	if cfg.VaultID == "" {
		return s + " · not synced yet — run `sme sync`"
	}
	if pending > 0 {
		return fmt.Sprintf("%s · %d revision(s) waiting to push", s, pending)
	}
	return s + " · up to date"
}
