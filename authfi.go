// Package authfi provides middleware and helpers for Go apps using AuthFI.
//
// Usage:
//
//	auth := authfi.New(authfi.Config{
//	    Tenant:        "acme",
//	    APIKey:        "sk_live_...",
//	    ApplicationID: "client-id",   // optional
//	    AutoSync:      true,
//	})
//
//	// chi router
//	r.With(auth.Require("read:users")).Get("/api/users", handler)
//
//	// net/http
//	http.Handle("/api/users", auth.Require("read:users")(handler))
//
//	// Start — syncs permissions
//	auth.Start()
package authfi

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Config struct {
	Tenant        string
	APIKey        string
	APIURL        string // default: https://api.authfi.app
	ApplicationID string // client_id of your application
	ClientSecret  string // client_secret — required for cloud identity
	AutoSync      bool
	JWKSRefresh   time.Duration // default: 5 min
}

type Client struct {
	cfg         Config
	permissions map[string]*string // name → description
	mu          sync.Mutex
	jwks        *jwksCache
}

type Claims struct {
	Subject       string   `json:"sub"`
	Email         string   `json:"email"`
	EmailVerified bool     `json:"email_verified"`
	Name          string   `json:"name"`
	Roles         []string `json:"roles"`
	Permissions   []string `json:"permissions"`
	TenantID      string   `json:"tenant_id"`
	OrgID         string   `json:"org_id"`
	OrgSlug       string   `json:"org_slug"`
	OrgRole       string   `json:"org_role"`
	IssuedAt      int64    `json:"iat"`
	ExpiresAt     int64    `json:"exp"`
	Issuer        string   `json:"iss"`
}

type contextKey struct{}

func New(cfg Config) *Client {
	if cfg.APIURL == "" {
		cfg.APIURL = "https://api.authfi.app"
	}
	if cfg.JWKSRefresh == 0 {
		cfg.JWKSRefresh = 5 * time.Minute
	}
	return &Client{
		cfg:         cfg,
		permissions: make(map[string]*string),
		jwks:        &jwksCache{ttl: cfg.JWKSRefresh},
	}
}

// Require returns middleware that validates JWT and checks all listed permissions.
func (c *Client) Require(permissions ...string) func(http.Handler) http.Handler {
	// Register for auto-sync
	for _, p := range permissions {
		c.RegisterPermission(p, "")
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, err := c.authenticate(r)
			if err != nil {
				http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusUnauthorized)
				return
			}

			userPerms := toSet(claims.Permissions)
			for _, required := range permissions {
				if !userPerms[required] {
					http.Error(w, fmt.Sprintf(`{"error":"insufficient permissions","missing":"%s"}`, required), http.StatusForbidden)
					return
				}
			}

			ctx := context.WithValue(r.Context(), contextKey{}, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireRole returns middleware that validates JWT and checks for any listed role.
func (c *Client) RequireRole(roles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, err := c.authenticate(r)
			if err != nil {
				http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusUnauthorized)
				return
			}

			userRoles := toSet(claims.Roles)
			found := false
			for _, role := range roles {
				if userRoles[role] {
					found = true
					break
				}
			}
			if !found {
				http.Error(w, `{"error":"insufficient role"}`, http.StatusForbidden)
				return
			}

			ctx := context.WithValue(r.Context(), contextKey{}, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// Authenticate returns middleware that validates JWT without permission checks.
func (c *Client) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, err := c.authenticate(r)
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), contextKey{}, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetUser extracts claims from request context (set by middleware).
func GetUser(ctx context.Context) *Claims {
	claims, _ := ctx.Value(contextKey{}).(*Claims)
	return claims
}

// RegisterPermission registers a permission for auto-sync.
func (c *Client) RegisterPermission(name, description string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if description != "" {
		c.permissions[name] = &description
	} else if _, exists := c.permissions[name]; !exists {
		c.permissions[name] = nil
	}
}

// Start pre-fetches JWKS and syncs permissions.
func (c *Client) Start() error {
	authURL := fmt.Sprintf("%s/v1/%s/.well-known/jwks.json", c.cfg.APIURL, c.cfg.Tenant)
	if err := c.jwks.refresh(authURL); err != nil {
		return fmt.Errorf("authfi: JWKS fetch failed: %w", err)
	}

	if c.cfg.AutoSync {
		return c.Sync()
	}
	return nil
}

// Sync pushes registered permissions to AuthFI.
func (c *Client) Sync() error {
	c.mu.Lock()
	if len(c.permissions) == 0 {
		c.mu.Unlock()
		return nil
	}

	type perm struct {
		Name        string  `json:"name"`
		Description *string `json:"description,omitempty"`
	}
	perms := make([]perm, 0, len(c.permissions))
	for name, desc := range c.permissions {
		perms = append(perms, perm{Name: name, Description: desc})
	}
	c.mu.Unlock()

	body := map[string]interface{}{"permissions": perms}
	if c.cfg.ApplicationID != "" {
		body["application_id"] = c.cfg.ApplicationID
	}

	data, _ := json.Marshal(body)
	url := fmt.Sprintf("%s/manage/v1/%s/permissions/sync", c.cfg.APIURL, c.cfg.Tenant)
	req, _ := http.NewRequest("PUT", url, bytes.NewReader(data))
	req.Header.Set("X-API-Key", c.cfg.APIKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("authfi: sync failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("authfi: sync failed (%d): %s", resp.StatusCode, string(b))
	}

	var result struct{ Synced, Total int }
	json.NewDecoder(resp.Body).Decode(&result)
	fmt.Printf("[authfi] Synced %d permissions (%d total)\n", result.Synced, result.Total)
	return nil
}

// CloudCredentials gets cloud provider credentials using an AuthFI user token.
// Requires ApplicationID and ClientSecret in Config — cloud credentials are scoped
// per application so each app can only access the cloud resources its IAM role permits.
func (c *Client) CloudCredentials(userToken, provider string, opts map[string]string) (map[string]interface{}, error) {
	if c.cfg.ApplicationID == "" || c.cfg.ClientSecret == "" {
		return nil, fmt.Errorf("authfi: ApplicationID and ClientSecret required for cloud credentials")
	}

	body := map[string]interface{}{
		"provider": provider,
		"ttl":      900,
	}
	for k, v := range opts {
		body[k] = v
	}

	data, _ := json.Marshal(body)
	authURL := fmt.Sprintf("%s/v1/%s/cloud/credentials", c.cfg.APIURL, c.cfg.Tenant)
	req, _ := http.NewRequest("POST", authURL, bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+userToken)
	req.Header.Set("X-Client-ID", c.cfg.ApplicationID)
	req.Header.Set("X-Client-Secret", c.cfg.ClientSecret)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cloud credentials request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("cloud credentials failed (%d): %s", resp.StatusCode, string(b))
	}

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	return result, nil
}

// CloudToken gets a raw OIDC token for manual federation.
// Requires ApplicationID and ClientSecret in Config.
func (c *Client) CloudToken(userToken, audience string, ttl int) (string, error) {
	if c.cfg.ApplicationID == "" || c.cfg.ClientSecret == "" {
		return "", fmt.Errorf("authfi: ApplicationID and ClientSecret required for cloud token")
	}

	body, _ := json.Marshal(map[string]interface{}{"audience": audience, "ttl": ttl})
	authURL := fmt.Sprintf("%s/v1/%s/cloud/token", c.cfg.APIURL, c.cfg.Tenant)
	req, _ := http.NewRequest("POST", authURL, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+userToken)
	req.Header.Set("X-Client-ID", c.cfg.ApplicationID)
	req.Header.Set("X-Client-Secret", c.cfg.ClientSecret)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result struct{ Token string `json:"token"` }
	json.NewDecoder(resp.Body).Decode(&result)
	return result.Token, nil
}

func (c *Client) authenticate(r *http.Request) (*Claims, error) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return nil, fmt.Errorf("missing authorization")
	}
	token := strings.TrimPrefix(auth, "Bearer ")
	return c.VerifyToken(token)
}

// VerifyToken decodes and verifies a JWT using the tenant's JWKS.
func (c *Client) VerifyToken(token string) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	// Decode header
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid token header")
	}
	var header struct {
		Kid string `json:"kid"`
		Alg string `json:"alg"`
	}
	json.Unmarshal(headerBytes, &header)

	// Decode payload
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid token payload")
	}
	var claims Claims
	json.Unmarshal(payloadBytes, &claims)

	// Check expiry
	if claims.ExpiresAt > 0 && claims.ExpiresAt < time.Now().Unix() {
		return nil, fmt.Errorf("token expired")
	}

	// Verify signature
	authURL := fmt.Sprintf("%s/v1/%s/.well-known/jwks.json", c.cfg.APIURL, c.cfg.Tenant)
	key, err := c.jwks.getKey(header.Kid, authURL)
	if err != nil {
		return nil, err
	}

	signedData := []byte(parts[0] + "." + parts[1])
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("invalid signature encoding")
	}

	hashed := sha256.Sum256(signedData)
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, hashed[:], sigBytes); err != nil {
		return nil, fmt.Errorf("invalid signature")
	}

	return &claims, nil
}

// --- helpers ---

func toSet(s []string) map[string]bool {
	m := make(map[string]bool, len(s))
	for _, v := range s {
		m[v] = true
	}
	return m
}

// --- JWKS cache ---

type jwksCache struct {
	mu      sync.RWMutex
	keys    map[string]*rsa.PublicKey
	fetched time.Time
	ttl     time.Duration
}

func (j *jwksCache) getKey(kid, url string) (*rsa.PublicKey, error) {
	j.mu.RLock()
	if key, ok := j.keys[kid]; ok && time.Since(j.fetched) < j.ttl {
		j.mu.RUnlock()
		return key, nil
	}
	j.mu.RUnlock()

	if err := j.refresh(url); err != nil {
		return nil, err
	}

	j.mu.RLock()
	defer j.mu.RUnlock()
	key, ok := j.keys[kid]
	if !ok {
		return nil, fmt.Errorf("unknown signing key: %s", kid)
	}
	return key, nil
}

func (j *jwksCache) refresh(url string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var jwks struct {
		Keys []struct {
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return err
	}

	keys := make(map[string]*rsa.PublicKey)
	for _, k := range jwks.Keys {
		nBytes, _ := base64.RawURLEncoding.DecodeString(k.N)
		eBytes, _ := base64.RawURLEncoding.DecodeString(k.E)

		n := new(big.Int).SetBytes(nBytes)
		e := 0
		for _, b := range eBytes {
			e = e<<8 + int(b)
		}

		keys[k.Kid] = &rsa.PublicKey{N: n, E: e}
	}

	j.mu.Lock()
	j.keys = keys
	j.fetched = time.Now()
	j.mu.Unlock()
	return nil
}
