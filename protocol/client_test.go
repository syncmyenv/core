package protocol

import "testing"

func TestValidateURL(t *testing.T) {
	ok := map[string]string{
		"https://cloud.syncmyenv.com": "https://cloud.syncmyenv.com",
		"cloud.syncmyenv.com":         "https://cloud.syncmyenv.com",
		" env.mycompany.com/ ":        "https://env.mycompany.com",
		"https://example.com/sme/":    "https://example.com/sme",
		"http://localhost:8080":       "http://localhost:8080",
		"http://192.168.1.20:8080":    "http://192.168.1.20:8080",
		"http://127.0.0.1:8080":       "http://127.0.0.1:8080",
		"env.home.lan:8443":           "https://env.home.lan:8443",
	}
	for in, want := range ok {
		got, err := ValidateURL(in)
		if err != nil || got != want {
			t.Errorf("ValidateURL(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"http://env.mycompany.com", "ftp://x.com", "https://", ""} {
		if _, err := ValidateURL(bad); err == nil {
			t.Errorf("ValidateURL(%q) accepted", bad)
		}
	}
}
