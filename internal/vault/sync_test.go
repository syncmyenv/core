package vault

import "testing"

func TestSafeImportPath(t *testing.T) {
	ok := []string{"~/Projects/app/.env", "~/code/x/.env.local", "/srv/app/.env.production", "~/w/env", "~/w/env.staging"}
	bad := []string{
		"", ".env", "Projects/.env", // not anchored
		"~/.bashrc", "~/.ssh/authorized_keys", "/etc/passwd", "~/app/config.json", // not env files
		"~/../../etc/.env", "~/a/../../.env", // traversal
		"~/app/.env.example", // templates aren't protected, so never imported
		"~/app/.env\x00.sh",
	}
	for _, p := range ok {
		if !SafeImportPath(p) {
			t.Errorf("rejected %q", p)
		}
	}
	for _, p := range bad {
		if SafeImportPath(p) {
			t.Errorf("accepted %q", p)
		}
	}
}

func TestPortablePaths(t *testing.T) {
	t.Setenv("HOME", "/home/alice")
	if got := ToPortable("/home/alice/Projects/app/.env"); got != "~/Projects/app/.env" {
		t.Fatal(got)
	}
	t.Setenv("HOME", "/Users/bob")
	if got := FromPortable("~/Projects/app/.env"); got != "/Users/bob/Projects/app/.env" {
		t.Fatal(got)
	}
	if got := ToPortable("/srv/app/.env"); got != "/srv/app/.env" {
		t.Fatal(got)
	}
}
