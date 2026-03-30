package authfi

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	c := New(Config{Tenant: "acme", APIKey: "sk_test"})
	if c.cfg.Tenant != "acme" {
		t.Fatalf("expected tenant acme, got %s", c.cfg.Tenant)
	}
	if c.cfg.APIURL != "https://api.authfi.app" {
		t.Fatalf("expected default API URL, got %s", c.cfg.APIURL)
	}
	if c.cfg.JWKSRefresh != 5*time.Minute {
		t.Fatalf("expected 5m JWKS refresh, got %v", c.cfg.JWKSRefresh)
	}
}

func TestNewCustomURL(t *testing.T) {
	c := New(Config{Tenant: "acme", APIKey: "sk_test", APIURL: "https://custom.api.com"})
	if c.cfg.APIURL != "https://custom.api.com" {
		t.Fatalf("expected custom URL, got %s", c.cfg.APIURL)
	}
}

func TestRegisterPermission(t *testing.T) {
	c := New(Config{Tenant: "acme", APIKey: "sk_test"})

	c.RegisterPermission("read:users", "Read user data")
	c.RegisterPermission("write:users", "")
	c.RegisterPermission("read:users", "") // duplicate — should not overwrite

	if len(c.permissions) != 2 {
		t.Fatalf("expected 2 permissions, got %d", len(c.permissions))
	}
	if c.permissions["read:users"] == nil || *c.permissions["read:users"] != "Read user data" {
		t.Fatal("expected read:users to have description")
	}
	if c.permissions["write:users"] != nil {
		t.Fatal("expected write:users to have nil description")
	}
}

func TestGetUserFromContext(t *testing.T) {
	claims := &Claims{Subject: "usr_123", Email: "test@acme.com"}
	ctx := context.WithValue(context.Background(), contextKey{}, claims)

	got := GetUser(ctx)
	if got == nil {
		t.Fatal("expected claims from context")
	}
	if got.Subject != "usr_123" {
		t.Fatalf("expected usr_123, got %s", got.Subject)
	}
}

func TestGetUserEmptyContext(t *testing.T) {
	got := GetUser(context.Background())
	if got != nil {
		t.Fatal("expected nil from empty context")
	}
}

func TestToSet(t *testing.T) {
	s := toSet([]string{"a", "b", "c"})
	if !s["a"] || !s["b"] || !s["c"] {
		t.Fatal("expected all keys to be true")
	}
	if s["d"] {
		t.Fatal("expected d to be false")
	}
}

// --- JWT verification tests ---

func generateTestToken(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]interface{}) string {
	t.Helper()

	header := map[string]string{"alg": "RS256", "typ": "JWT", "kid": kid}
	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	signedData := []byte(headerB64 + "." + claimsB64)
	hashed := sha256.Sum256(signedData)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hashed[:])
	if err != nil {
		t.Fatal(err)
	}
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	return headerB64 + "." + claimsB64 + "." + sigB64
}

func setupJWKSServer(t *testing.T, key *rsa.PublicKey, kid string) *httptest.Server {
	t.Helper()

	nB64 := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
	eBytes := big.NewInt(int64(key.E)).Bytes()
	eB64 := base64.RawURLEncoding.EncodeToString(eBytes)

	jwksResponse := fmt.Sprintf(`{"keys":[{"kid":"%s","kty":"RSA","alg":"RS256","use":"sig","n":"%s","e":"%s"}]}`, kid, nB64, eB64)

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(jwksResponse))
	}))
}

func TestVerifyValidToken(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	kid := "test-key-1"

	srv := setupJWKSServer(t, &key.PublicKey, kid)
	defer srv.Close()

	c := New(Config{Tenant: "acme", APIURL: srv.URL})

	token := generateTestToken(t, key, kid, map[string]interface{}{
		"sub":         "usr_123",
		"email":       "jane@acme.com",
		"name":        "Jane Smith",
		"roles":       []string{"admin", "editor"},
		"permissions": []string{"read:users", "write:users"},
		"tenant_id":   "tnt_456",
		"org_slug":    "acme-corp",
		"exp":         time.Now().Add(time.Hour).Unix(),
		"iat":         time.Now().Unix(),
		"iss":         "https://acme.authfi.app",
	})

	claims, err := c.VerifyToken(token)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if claims.Subject != "usr_123" {
		t.Fatalf("expected usr_123, got %s", claims.Subject)
	}
	if claims.Email != "jane@acme.com" {
		t.Fatalf("expected jane@acme.com, got %s", claims.Email)
	}
	if len(claims.Roles) != 2 {
		t.Fatalf("expected 2 roles, got %d", len(claims.Roles))
	}
	if len(claims.Permissions) != 2 {
		t.Fatalf("expected 2 permissions, got %d", len(claims.Permissions))
	}
	if claims.OrgSlug != "acme-corp" {
		t.Fatalf("expected acme-corp, got %s", claims.OrgSlug)
	}
}

func TestVerifyExpiredToken(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	kid := "test-key-1"

	srv := setupJWKSServer(t, &key.PublicKey, kid)
	defer srv.Close()

	c := New(Config{Tenant: "acme", APIURL: srv.URL})

	token := generateTestToken(t, key, kid, map[string]interface{}{
		"sub": "usr_123",
		"exp": time.Now().Add(-time.Hour).Unix(),
	})

	_, err := c.VerifyToken(token)
	if err == nil {
		t.Fatal("expected error for expired token")
	}
	if err.Error() != "token expired" {
		t.Fatalf("expected 'token expired', got %s", err.Error())
	}
}

func TestVerifyInvalidSignature(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	kid := "test-key-1"

	// JWKS server has otherKey, but token signed with key
	srv := setupJWKSServer(t, &otherKey.PublicKey, kid)
	defer srv.Close()

	c := New(Config{Tenant: "acme", APIURL: srv.URL})

	token := generateTestToken(t, key, kid, map[string]interface{}{
		"sub": "usr_123",
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	_, err := c.VerifyToken(token)
	if err == nil {
		t.Fatal("expected error for invalid signature")
	}
}

func TestVerifyInvalidFormat(t *testing.T) {
	c := New(Config{Tenant: "acme", APIKey: "sk_test"})

	_, err := c.VerifyToken("not-a-jwt")
	if err == nil {
		t.Fatal("expected error for invalid format")
	}
}

// --- Middleware tests ---

func TestRequireMiddleware(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	kid := "test-key-1"

	srv := setupJWKSServer(t, &key.PublicKey, kid)
	defer srv.Close()

	c := New(Config{Tenant: "acme", APIURL: srv.URL})

	token := generateTestToken(t, key, kid, map[string]interface{}{
		"sub":         "usr_123",
		"permissions": []string{"read:users"},
		"exp":         time.Now().Add(time.Hour).Unix(),
	})

	handler := c.Require("read:users")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := GetUser(r.Context())
		if claims == nil {
			t.Fatal("expected claims in context")
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(claims.Subject))
	}))

	req := httptest.NewRequest("GET", "/api/users", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != "usr_123" {
		t.Fatalf("expected usr_123, got %s", rec.Body.String())
	}
}

func TestRequireMiddlewareMissingPermission(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	kid := "test-key-1"

	srv := setupJWKSServer(t, &key.PublicKey, kid)
	defer srv.Close()

	c := New(Config{Tenant: "acme", APIURL: srv.URL})

	token := generateTestToken(t, key, kid, map[string]interface{}{
		"sub":         "usr_123",
		"permissions": []string{"read:users"},
		"exp":         time.Now().Add(time.Hour).Unix(),
	})

	handler := c.Require("delete:users")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/api/users", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}

func TestRequireMiddlewareNoAuth(t *testing.T) {
	c := New(Config{Tenant: "acme", APIKey: "sk_test"})

	handler := c.Require("read:users")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/api/users", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestRequireRoleMiddleware(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	kid := "test-key-1"

	srv := setupJWKSServer(t, &key.PublicKey, kid)
	defer srv.Close()

	c := New(Config{Tenant: "acme", APIURL: srv.URL})

	token := generateTestToken(t, key, kid, map[string]interface{}{
		"sub":   "usr_123",
		"roles": []string{"editor"},
		"exp":   time.Now().Add(time.Hour).Unix(),
	})

	// Should pass — has editor role
	handler := c.RequireRole("admin", "editor")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	// Should fail — doesn't have superadmin
	handler2 := c.RequireRole("superadmin")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not be called")
	}))

	req2 := httptest.NewRequest("GET", "/", nil)
	req2.Header.Set("Authorization", "Bearer "+token)
	rec2 := httptest.NewRecorder()
	handler2.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec2.Code)
	}
}

func TestAuthenticateMiddleware(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	kid := "test-key-1"

	srv := setupJWKSServer(t, &key.PublicKey, kid)
	defer srv.Close()

	c := New(Config{Tenant: "acme", APIURL: srv.URL})

	token := generateTestToken(t, key, kid, map[string]interface{}{
		"sub": "usr_123",
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	handler := c.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := GetUser(r.Context())
		if claims == nil || claims.Subject != "usr_123" {
			t.Fatal("expected claims in context")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

// --- Sync tests ---

func TestSyncEmpty(t *testing.T) {
	c := New(Config{Tenant: "acme", APIKey: "sk_test"})
	// Empty sync should be no-op, no error
	err := c.Sync()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestSyncSendsPermissions(t *testing.T) {
	var received map[string]interface{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/manage/v1/acme/permissions/sync" {
			json.NewDecoder(r.Body).Decode(&received)
			w.Write([]byte(`{"synced":2,"total":2}`))
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	c := New(Config{Tenant: "acme", APIKey: "sk_test", APIURL: srv.URL})
	c.RegisterPermission("read:users", "Read users")
	c.RegisterPermission("write:users", "")

	err := c.Sync()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if received == nil {
		t.Fatal("expected sync request to be sent")
	}

	perms, ok := received["permissions"].([]interface{})
	if !ok || len(perms) != 2 {
		t.Fatalf("expected 2 permissions in sync, got %v", received)
	}
}
