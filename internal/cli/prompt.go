package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// prompter reads secrets from the terminal (hidden) or, with --password-stdin,
// one per line from stdin — for scripts and tests. Never from flags or env:
// those end up in shell history and /proc.
type prompter struct {
	cmd   *cobra.Command
	stdin bool
	br    *bufio.Reader
}

func newPrompter(cmd *cobra.Command, fromStdin bool) *prompter {
	return &prompter{cmd: cmd, stdin: fromStdin, br: bufio.NewReader(cmd.InOrStdin())}
}

func (p *prompter) secret(label string) (string, error) {
	if p.stdin {
		line, err := p.br.ReadString('\n')
		if err != nil && !(errors.Is(err, io.EOF) && line != "") {
			return "", fmt.Errorf("reading %s from stdin: %w", label, err)
		}
		return strings.TrimRight(line, "\r\n"), nil
	}
	f, ok := p.cmd.InOrStdin().(*os.File)
	if !ok || !term.IsTerminal(int(f.Fd())) {
		return "", errors.New("stdin is not a terminal — use --password-stdin")
	}
	fmt.Fprintf(p.cmd.ErrOrStderr(), "%s: ", label)
	b, err := term.ReadPassword(int(f.Fd()))
	fmt.Fprintln(p.cmd.ErrOrStderr())
	return string(b), err
}

// newPassword asks twice on a terminal (once with --password-stdin).
func (p *prompter) newPassword(label string) (string, error) {
	pw, err := p.secret(label)
	if err != nil || p.stdin {
		return pw, err
	}
	again, err := p.secret("confirm " + label)
	if err != nil {
		return "", err
	}
	if pw != again {
		return "", errors.New("passwords don't match")
	}
	return pw, nil
}
