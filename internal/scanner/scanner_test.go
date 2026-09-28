package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsEnvFile(t *testing.T) {
	yes := []string{".env", ".env.local", ".env.production", "env", "env.local"}
	no := []string{".envrc", "environment", "my.env", ".env.", "env.", "dotenv"}
	for _, n := range yes {
		if !IsEnvFile(n) {
			t.Errorf("IsEnvFile(%q) = false, want true", n)
		}
	}
	for _, n := range no {
		if IsEnvFile(n) {
			t.Errorf("IsEnvFile(%q) = true, want false", n)
		}
	}
}

func write(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("A=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestScan(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "spotify/.env"))
	write(t, filepath.Join(root, "spotify/.env.local"))
	write(t, filepath.Join(root, "spotify/.env.example"))
	write(t, filepath.Join(root, "spotify/apps/api/.env"))
	write(t, filepath.Join(root, "spotify/node_modules/foo/.env"))
	write(t, filepath.Join(root, "loose/env.production"))
	if err := os.MkdirAll(filepath.Join(root, "spotify/.git"), 0o755); err != nil {
		t.Fatal(err)
	}

	res, err := Scan([]string{root}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Result{}
	for _, r := range res {
		got[filepath.ToSlash(r.RelPath)] = r
	}
	want := []string{"loose/env.production", "spotify/.env", "spotify/.env.local", "spotify/apps/api/.env"}
	if len(res) != len(want) {
		t.Fatalf("got %d results %v, want %v", len(res), got, want)
	}
	for _, w := range want {
		if _, ok := got[w]; !ok {
			t.Errorf("missing %s", w)
		}
	}
	if r := got["spotify/apps/api/.env"]; !r.InGitRepo || r.ProjectName != "spotify" {
		t.Errorf("monorepo file should belong to git project spotify, got %+v", r)
	}
	if r := got["loose/env.production"]; r.InGitRepo || r.ProjectName != "loose" {
		t.Errorf("non-git file should use its dir as project, got %+v", r)
	}

	res, _ = Scan([]string{root}, Options{IncludeTemplate: true})
	if len(res) != 5 {
		t.Errorf("with templates: got %d, want 5", len(res))
	}
}
