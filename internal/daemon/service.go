package daemon

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"text/template"

	"github.com/syncmyenv/core/internal/config"
)

// Label identifies the service to launchd / systemd.
const (
	launchdLabel = "com.syncmyenv.daemon"
	systemdUnit  = "syncmyenv.service"
)

// ErrUnsupported is returned on platforms without service integration yet.
var ErrUnsupported = errors.New("automatic start isn't supported on this OS yet — run `sme daemon` yourself")

// Service describes how the daemon is installed on this machine.
type Service struct {
	OS      string // darwin | linux
	Exe     string // absolute path to the sme binary
	Home    string // SYNCMYENV_HOME
	LogPath string
	Path    string // where the unit/plist file goes
}

// NewService resolves paths for the current OS and binary.
func NewService() (*Service, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return nil, err
	}
	if strings.Contains(exe, string(filepath.Separator)+"go-build") {
		return nil, errors.New("refusing to install a `go run` temp binary — build it first (make build)")
	}
	home, err := config.Home()
	if err != nil {
		return nil, err
	}
	userHome, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	s := &Service{OS: runtime.GOOS, Exe: exe, Home: home, LogPath: filepath.Join(home, "daemon.log")}
	switch s.OS {
	case "darwin":
		s.Path = filepath.Join(userHome, "Library", "LaunchAgents", launchdLabel+".plist")
	case "linux":
		cfg := os.Getenv("XDG_CONFIG_HOME")
		if cfg == "" {
			cfg = filepath.Join(userHome, ".config")
		}
		s.Path = filepath.Join(cfg, "systemd", "user", systemdUnit)
	default:
		return nil, ErrUnsupported
	}
	return s, nil
}

var plistTmpl = template.Must(template.New("plist").Funcs(template.FuncMap{"x": xmlEscape}).Parse(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>` + launchdLabel + `</string>
  <key>ProgramArguments</key>
  <array>
    <string>{{x .Exe}}</string>
    <string>daemon</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>SYNCMYENV_HOME</key><string>{{x .Home}}</string>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
  <key>ThrottleInterval</key><integer>10</integer>
  <key>ProcessType</key><string>Background</string>
  <key>StandardOutPath</key><string>{{x .LogPath}}</string>
  <key>StandardErrorPath</key><string>{{x .LogPath}}</string>
</dict>
</plist>
`))

var unitTmpl = template.Must(template.New("unit").Parse(`[Unit]
Description=SyncMyEnv — versions & backs up your .env files
Documentation=https://syncmyenv.com

[Service]
ExecStart="{{.Exe}}" daemon
Environment="SYNCMYENV_HOME={{.Home}}"
Restart=on-failure
RestartSec=10
Nice=10

[Install]
WantedBy=default.target
`))

// Render returns the plist (macOS) or unit file (Linux) contents.
func (s *Service) Render() (string, error) {
	var b bytes.Buffer
	t := unitTmpl
	if s.OS == "darwin" {
		t = plistTmpl
	}
	err := t.Execute(&b, s)
	return b.String(), err
}

// Install writes the service file and starts it. Re-installing replaces it.
func (s *Service) Install() error {
	body, err := s.Render()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(s.Path, []byte(body), 0o644); err != nil {
		return err
	}
	switch s.OS {
	case "darwin":
		domain := fmt.Sprintf("gui/%d", os.Getuid())
		_ = run("launchctl", "bootout", domain+"/"+launchdLabel) // fine if not loaded
		return run("launchctl", "bootstrap", domain, s.Path)
	default:
		if err := run("systemctl", "--user", "daemon-reload"); err != nil {
			return err
		}
		return run("systemctl", "--user", "enable", "--now", systemdUnit)
	}
}

// Uninstall stops the service and removes its file.
func (s *Service) Uninstall() error {
	switch s.OS {
	case "darwin":
		_ = run("launchctl", "bootout", fmt.Sprintf("gui/%d/%s", os.Getuid(), launchdLabel))
	default:
		_ = run("systemctl", "--user", "disable", "--now", systemdUnit)
	}
	if err := os.Remove(s.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if s.OS == "linux" {
		_ = run("systemctl", "--user", "daemon-reload")
	}
	return nil
}

// Installed reports whether the service file exists.
func (s *Service) Installed() bool {
	_, err := os.Stat(s.Path)
	return err == nil
}

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func xmlEscape(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}
