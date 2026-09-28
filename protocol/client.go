package protocol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// APIError is a non-2xx response.
type APIError struct {
	Status  int
	Code    string
	Message string
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("server: %s (%d %s)", e.Message, e.Status, e.Code)
	}
	return fmt.Sprintf("server: %d %s", e.Status, e.Code)
}

// IsStatus reports whether err is an APIError with the given HTTP status.
func IsStatus(err error, status int) bool {
	var e *APIError
	return errors.As(err, &e) && e.Status == status
}

// Client talks to a SyncMyEnv server. Token is a device token (sme_dev_…).
type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
	UA      string
}

// ValidateURL normalizes a server address and requires https, except for
// localhost / private LAN development. Without a scheme, a public domain
// ("env.example.com") means https://; a local or private address
// ("localhost:8080", "192.168.1.20:8080") means http://.
func ValidateURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if !strings.Contains(raw, "://") {
		scheme := "https://"
		if h, err := url.Parse("x://" + raw); err == nil && isLocal(h.Hostname()) {
			scheme = "http://"
		}
		raw = scheme + raw
	}
	u, err := url.Parse(strings.TrimRight(raw, "/"))
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return "", fmt.Errorf("invalid server URL %q (want https://host)", raw)
	}
	if u.Scheme == "http" && !isLocal(u.Hostname()) {
		return "", fmt.Errorf("refusing plain http:// for %s — tokens would travel unencrypted; use https", u.Host)
	}
	u.Path = strings.TrimRight(u.Path, "/")
	return u.String(), nil
}

// Discover turns what the user typed into the URL of a SyncMyEnv server that
// actually answers. With an explicit scheme it only validates. Without one it
// probes https:// first and, for local/LAN hosts only, falls back to http://
// — so "localhost:8443" works whether that port speaks TLS or not.
func Discover(ctx context.Context, raw string, hc *http.Client) (string, error) {
	raw = strings.TrimSpace(raw)
	if strings.Contains(raw, "://") {
		return ValidateURL(raw)
	}
	if hc == nil {
		hc = &http.Client{Timeout: 5 * time.Second}
	}
	candidates := []string{"https://" + raw}
	if h, err := url.Parse("x://" + raw); err == nil && isLocal(h.Hostname()) {
		candidates = append(candidates, "http://"+raw)
	}
	var tried []string
	for _, c := range candidates {
		u, err := ValidateURL(c)
		if err != nil {
			return "", err
		}
		if probe(ctx, hc, u) {
			return u, nil
		}
		tried = append(tried, u)
	}
	return "", fmt.Errorf("no SyncMyEnv server answering at %s", strings.Join(tried, " or "))
}

// probe reports whether base serves the SyncMyEnv health endpoint.
func probe(ctx context.Context, hc *http.Client, base string) bool {
	req, err := http.NewRequestWithContext(ctx, "GET", base+"/api/v1/health", nil)
	if err != nil {
		return false
	}
	res, err := hc.Do(req)
	if err != nil {
		return false
	}
	defer res.Body.Close()
	var h struct {
		Status string `json:"status"`
	}
	return res.StatusCode == http.StatusOK && json.NewDecoder(io.LimitReader(res.Body, 4096)).Decode(&h) == nil && h.Status == "ok"
}

func isLocal(host string) bool {
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && (ip.IsLoopback() || ip.IsPrivate())
}

func (c *Client) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *Client) do(ctx context.Context, method, path string, body io.Reader, contentType string, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+"/api/v1"+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	ua := c.UA
	if ua == "" {
		ua = "syncmyenv-cli"
	}
	req.Header.Set("User-Agent", ua)
	res, err := c.http().Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 {
		var eb ErrorBody
		raw, _ := io.ReadAll(io.LimitReader(res.Body, 64<<10))
		_ = json.Unmarshal(raw, &eb)
		code := eb.Error.Code
		if code == "" { // RFC 8628 style {"error": "authorization_pending"}
			var flat struct {
				Error string `json:"error"`
			}
			if json.Unmarshal(raw, &flat) == nil {
				code = flat.Error
			}
		}
		return &APIError{Status: res.StatusCode, Code: code, Message: eb.Error.Message}
	}
	if out == nil {
		return nil
	}
	if b, ok := out.(*[]byte); ok {
		*b, err = io.ReadAll(io.LimitReader(res.Body, MaxObjectSize+1))
		if err == nil && len(*b) > MaxObjectSize {
			return errors.New("object too large")
		}
		return err
	}
	return json.NewDecoder(res.Body).Decode(out)
}

func (c *Client) json(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	ct := ""
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body, ct = bytes.NewReader(b), "application/json"
	}
	return c.do(ctx, method, path, body, ct, out)
}

// ---- auth ----

func (c *Client) DeviceCode(ctx context.Context, name string) (*DeviceCodeResponse, error) {
	var out DeviceCodeResponse
	return &out, c.json(ctx, "POST", "/auth/device/code", DeviceCodeRequest{DeviceName: name}, &out)
}

// DeviceToken polls once. While waiting it returns an *APIError whose Code is
// authorization_pending or slow_down.
func (c *Client) DeviceToken(ctx context.Context, deviceCode string) (*DeviceTokenResponse, error) {
	var out DeviceTokenResponse
	return &out, c.json(ctx, "POST", "/auth/device/token", DeviceTokenRequest{DeviceCode: deviceCode}, &out)
}

func (c *Client) Me(ctx context.Context) (*Me, error) {
	var out Me
	return &out, c.json(ctx, "GET", "/me", nil, &out)
}

// RevokeSelf revokes this device's own token (logout).
func (c *Client) RevokeSelf(ctx context.Context) error {
	return c.json(ctx, "DELETE", "/devices/self", nil, nil)
}

// ---- vaults ----

func (c *Client) Vaults(ctx context.Context) ([]Vault, error) {
	var out VaultList
	return out.Vaults, c.json(ctx, "GET", "/vaults", nil, &out)
}

func (c *Client) CreateVault(ctx context.Context, name string) (*Vault, error) {
	var out Vault
	return &out, c.json(ctx, "POST", "/vaults", CreateVaultRequest{Name: name}, &out)
}

func (c *Client) GetKeyring(ctx context.Context, vault string) ([]byte, error) {
	var out []byte
	return out, c.do(ctx, "GET", "/vaults/"+url.PathEscape(vault)+"/keyring", nil, "", &out)
}

func (c *Client) PutKeyring(ctx context.Context, vault string, keyfile []byte) error {
	return c.do(ctx, "PUT", "/vaults/"+url.PathEscape(vault)+"/keyring", bytes.NewReader(keyfile), "application/json", nil)
}

// ---- objects ----

func (c *Client) PutObject(ctx context.Context, vault string, data []byte) (string, error) {
	id := ObjectID(data)
	return id, c.do(ctx, "PUT", "/vaults/"+url.PathEscape(vault)+"/objects/"+id, bytes.NewReader(data), "application/octet-stream", nil)
}

// GetObject downloads a blob and verifies it matches its content address.
func (c *Client) GetObject(ctx context.Context, vault, id string) ([]byte, error) {
	var out []byte
	if err := c.do(ctx, "GET", "/vaults/"+url.PathEscape(vault)+"/objects/"+url.PathEscape(id), nil, "", &out); err != nil {
		return nil, err
	}
	if ObjectID(out) != id {
		return nil, errors.New("object integrity check failed (content doesn't match its id)")
	}
	return out, nil
}

// ---- log ----

func (c *Client) AppendLog(ctx context.Context, vault string, entries []LogEntry) error {
	return c.json(ctx, "POST", "/vaults/"+url.PathEscape(vault)+"/log", AppendLogRequest{Entries: entries}, &AppendLogResponse{})
}

func (c *Client) ReadLog(ctx context.Context, vault string, since int64) (*ReadLogResponse, error) {
	var out ReadLogResponse
	return &out, c.json(ctx, "GET", "/vaults/"+url.PathEscape(vault)+"/log?since="+strconv.FormatInt(since, 10), nil, &out)
}
