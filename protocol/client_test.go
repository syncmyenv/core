package protocol

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

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

func TestDiscover(t *testing.T) {
	health := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/health" {
			w.Write([]byte(`{"status":"ok","version":"t"}`))
			return
		}
		http.NotFound(w, r)
	})
	ctx := context.Background()

	// TLS-only local server: bare "127.0.0.1:port" must find https, not guess http.
	tlsSrv := httptest.NewTLSServer(health)
	defer tlsSrv.Close()
	host := strings.TrimPrefix(tlsSrv.URL, "https://")
	got, err := Discover(ctx, host, tlsSrv.Client())
	if err != nil || got != tlsSrv.URL {
		t.Fatalf("tls: got %q, %v", got, err)
	}

	// Plain-http local dev server: falls back to http.
	plain := httptest.NewServer(health)
	defer plain.Close()
	host = strings.TrimPrefix(plain.URL, "http://")
	got, err = Discover(ctx, host, plain.Client())
	if err != nil || got != plain.URL {
		t.Fatalf("plain: got %q, %v", got, err)
	}

	// Something that isn't SyncMyEnv.
	other := httptest.NewServer(http.NotFoundHandler())
	defer other.Close()
	if _, err := Discover(ctx, strings.TrimPrefix(other.URL, "http://"), other.Client()); err == nil || !strings.Contains(err.Error(), "no SyncMyEnv server") {
		t.Fatalf("non-sme server: %v", err)
	}

	// Explicit scheme: validated, not probed.
	if got, err := Discover(ctx, "https://env.example.com", nil); err != nil || got != "https://env.example.com" {
		t.Fatalf("explicit: %q %v", got, err)
	}
}
