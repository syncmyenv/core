package cli

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/syncmyenv/core/internal/config"
	"github.com/syncmyenv/core/internal/crypto"
	"github.com/syncmyenv/core/internal/vault"
)

func newInitCmd() *cobra.Command {
	var fromStdin bool
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Create a new encrypted vault",
		Long: `Create a new vault: a post-quantum age key (ML-KEM-768 + X25519), wrapped by
your master password (argon2id) and by a one-time recovery key.

The master password never leaves this machine. Write the recovery key down —
it is the only way back in if you forget the password.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := vault.LoadKeyFile(); err == nil {
				home, _ := config.Home()
				return fmt.Errorf("%w at %s", vault.ErrAlreadyInitialized, home)
			} else if !errors.Is(err, vault.ErrNotInitialized) {
				return err
			}
			pw, err := newPrompter(cmd, fromStdin).newPassword("master password")
			if err != nil {
				return err
			}
			if len(pw) < crypto.MinPasswordLen {
				return crypto.ErrWeakPassword
			}
			k, err := crypto.NewVaultKey()
			if err != nil {
				return err
			}
			rk, err := crypto.NewRecoveryKey()
			if err != nil {
				return err
			}
			f, err := crypto.NewKeyFile(k, pw, rk)
			if err != nil {
				return err
			}
			if err := vault.CreateKeyFile(f); err != nil {
				return err
			}
			home, _ := config.Home()
			printInit(cmd.OutOrStdout(), f, rk, home)
			return nil
		},
	}
	cmd.Flags().BoolVar(&fromStdin, "password-stdin", false, "read the password from stdin (one line)")
	return cmd
}

func printInit(w io.Writer, f *crypto.KeyFile, rk crypto.RecoveryKey, home string) {
	a := crypto.DefaultArgon
	fmt.Fprintf(w, "✓ vault created\n\n")
	fmt.Fprintf(w, "  fingerprint  %s\n", crypto.Fingerprint(f.Recipient))
	fmt.Fprintf(w, "  location     %s\n", home)
	fmt.Fprintf(w, "  crypto       age ML-KEM-768+X25519 · argon2id m=%dMiB t=%d p=%d\n\n", a.Memory/1024, a.Time, a.Threads)

	groups := strings.Split(rk.String(), "-")
	lines := []string{strings.Join(groups[:7], "-") + "-", "     " + strings.Join(groups[7:], "-")}
	width := max(len(lines[0]), len(lines[1]))
	title := "─ RECOVERY KEY "
	fmt.Fprintf(w, "  ┌%s%s┐\n", title, strings.Repeat("─", width+2-len([]rune(title))))
	for _, l := range lines {
		fmt.Fprintf(w, "  │ %-*s │\n", width, l)
	}
	fmt.Fprintf(w, "  └%s┘\n\n", strings.Repeat("─", width+2))
	fmt.Fprintln(w, "  This is the ONLY way back in if you forget your master password.")
	fmt.Fprintln(w, "  Nobody can reset it — not us, not support. Store it offline (paper,")
	fmt.Fprintln(w, "  password manager). It will not be shown again.")
}

func newStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show vault, watcher and sync status",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			w := cmd.OutOrStdout()
			home, err := config.Home()
			if err != nil {
				return err
			}
			f, err := vault.LoadKeyFile()
			if errors.Is(err, vault.ErrNotInitialized) {
				fmt.Fprintf(w, "vault        not initialized — run `sme init`\nlocation     %s\n", home)
				return nil
			} else if err != nil {
				return err
			}
			methods := []string{}
			if f.Password != nil {
				methods = append(methods, "password")
			}
			if f.Recovery != nil {
				methods = append(methods, "recovery key")
			}
			fmt.Fprintf(w, "vault        ✓ initialized\n")
			fmt.Fprintf(w, "fingerprint  %s\n", crypto.Fingerprint(f.Recipient))
			fmt.Fprintf(w, "created      %s\n", f.CreatedAt.Local().Format(time.DateTime))
			fmt.Fprintf(w, "unlock       %s\n", strings.Join(methods, ", "))
			fmt.Fprintf(w, "location     %s\n", home)
			fmt.Fprintf(w, "protected    — (coming next: `sme protect`)\n")
			return nil
		},
	}
}

func newKeysCmd() *cobra.Command {
	keys := &cobra.Command{Use: "keys", Short: "Manage the vault's master password and recovery key"}

	var fromStdin, useRecovery bool
	verify := &cobra.Command{
		Use:   "verify",
		Short: "Check that your master password (or recovery key) unlocks the vault",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			f, err := vault.LoadKeyFile()
			if err != nil {
				return err
			}
			if _, err := unlock(cmd, f, newPrompter(cmd, fromStdin), useRecovery); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "✓ unlocks vault %s\n", crypto.Fingerprint(f.Recipient))
			return nil
		},
	}
	verify.Flags().BoolVar(&fromStdin, "password-stdin", false, "read secrets from stdin (one per line)")
	verify.Flags().BoolVar(&useRecovery, "recovery", false, "verify the recovery key instead of the password")

	var pwStdin, pwRecovery bool
	passwd := &cobra.Command{
		Use:   "passwd",
		Short: "Change the master password (the recovery key stays valid)",
		Long: `Change the master password. Unlock with the current password, or with
--recovery if you've forgotten it. Your data doesn't need re-encrypting:
only the wrapped vault key changes.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			f, err := vault.LoadKeyFile()
			if err != nil {
				return err
			}
			p := newPrompter(cmd, pwStdin)
			k, err := unlock(cmd, f, p, pwRecovery)
			if err != nil {
				return err
			}
			pw, err := p.newPassword("new master password")
			if err != nil {
				return err
			}
			if err := f.SetPassword(k, pw); err != nil {
				return err
			}
			if err := vault.UpdateKeyFile(f); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "✓ master password changed")
			return nil
		},
	}
	passwd.Flags().BoolVar(&pwStdin, "password-stdin", false, "read secrets from stdin (one per line)")
	passwd.Flags().BoolVar(&pwRecovery, "recovery", false, "unlock with the recovery key (forgot password)")

	keys.AddCommand(verify, passwd)
	return keys
}

// unlock prompts for the password or recovery key and unwraps the vault key.
func unlock(cmd *cobra.Command, f *crypto.KeyFile, p *prompter, useRecovery bool) (*crypto.VaultKey, error) {
	if useRecovery {
		s, err := p.secret("recovery key")
		if err != nil {
			return nil, err
		}
		rk, err := crypto.ParseRecoveryKey(s)
		if err != nil {
			return nil, err
		}
		return f.UnlockWithRecovery(rk)
	}
	pw, err := p.secret("master password")
	if err != nil {
		return nil, err
	}
	return f.UnlockWithPassword(pw)
}
