package daemon

import (
	"errors"
	"strings"
	"testing"

	"github.com/syncmyenv/core/internal/config"
)

func TestLock(t *testing.T) {
	t.Setenv(config.HomeEnv, t.TempDir())
	if ok, _ := Running(); ok {
		t.Fatal("running before acquire")
	}
	l, err := Acquire()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Acquire(); !errors.Is(err, ErrRunning) {
		t.Fatalf("second acquire: %v", err)
	}
	if ok, pid := Running(); !ok || pid <= 0 {
		t.Fatalf("Running() = %v, %d", ok, pid)
	}
	l.Release()
	if ok, _ := Running(); ok {
		t.Fatal("still running after release")
	}
	l2, err := Acquire()
	if err != nil {
		t.Fatalf("reacquire: %v", err)
	}
	l2.Release()
}

func TestRender(t *testing.T) {
	for _, osName := range []string{"darwin", "linux"} {
		s := &Service{OS: osName, Exe: "/usr/local/bin/sme", Home: "/Users/c/.syncmyenv", LogPath: "/Users/c/.syncmyenv/daemon.log"}
		body, err := s.Render()
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"/usr/local/bin/sme", "daemon", "SYNCMYENV_HOME", "/Users/c/.syncmyenv"} {
			if !strings.Contains(body, want) {
				t.Errorf("%s: missing %q in\n%s", osName, want, body)
			}
		}
	}
}

func TestPlistEscapesPaths(t *testing.T) {
	s := &Service{OS: "darwin", Exe: "/Users/a&b/<bin>/sme", Home: "/h", LogPath: "/h/l"}
	body, _ := s.Render()
	if strings.Contains(body, "a&b") || !strings.Contains(body, "a&amp;b/&lt;bin&gt;") {
		t.Fatalf("not escaped:\n%s", body)
	}
}
