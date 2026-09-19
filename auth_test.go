package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestValidateUsername(t *testing.T) {
	tests := []struct {
		name     string
		username string
		wantErr  bool
	}{
		{"valid standard", "mradul_123", false},
		{"valid min length", "abc", false},
		{"valid alphanumeric", "Alice99", false},
		{"too short", "ab", true},
		{"too long", "a1234567890123456789012345678901", true},
		{"special character @", "user@name", true},
		{"special character dash", "user-name", true},
		{"space in username", "user name", true},
		{"reserved admin", "admin", true},
		{"reserved Admin uppercase", "Admin", true},
		{"reserved root", "root", true},
		{"reserved opaque", "opaque", true},
		{"reserved zarq", "zarq", true},
		{"reserved system", "system", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateUsername(tt.username)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateUsername(%q) error = %v, wantErr = %v", tt.username, err, tt.wantErr)
			}
		})
	}
}

func TestIPRateLimiter(t *testing.T) {
	// Limiter with burst capacity of 3, 1 token per second
	limiter := NewIPRateLimiter(1.0, 3.0)
	clientIP := "192.168.1.100"

	// First 3 requests should be allowed
	for i := 1; i <= 3; i++ {
		if !limiter.Allow(clientIP) {
			t.Fatalf("Request %d should have been allowed", i)
		}
	}

	// 4th immediate request should be denied
	if limiter.Allow(clientIP) {
		t.Fatalf("Request 4 should have been blocked by rate limiter")
	}

	// Different IP should still have full burst
	otherIP := "192.168.1.101"
	if !limiter.Allow(otherIP) {
		t.Fatalf("Request from new IP should have been allowed")
	}

	// Wait for token refill (1.1s = >1 token)
	time.Sleep(1100 * time.Millisecond)
	if !limiter.Allow(clientIP) {
		t.Fatalf("Request after refill interval should have been allowed")
	}
}

func TestValidateAvatarPrivacy(t *testing.T) {
	tests := []struct {
		input   string
		want    string
		wantErr bool
	}{
		{"everyone", "everyone", false},
		{"EVERYONE", "everyone", false},
		{" contacts ", "contacts", false},
		{"nobody", "nobody", false},
		{"Nobody", "nobody", false},
		{"public", "", true},
		{"friends_only", "", true},
		{"", "", true},
		{"random_string", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := validateAvatarPrivacy(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateAvatarPrivacy(%q) error = %v, wantErr = %v", tt.input, err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("validateAvatarPrivacy(%q) got = %q, want = %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestGetClientIP_UntrustedProxy(t *testing.T) {
	configureTrustedProxies("") // Clear trusted proxies

	req, _ := http.NewRequest("GET", "/profiles/me", nil)
	req.RemoteAddr = "203.0.113.50:12345"
	req.Header.Set("X-Forwarded-For", "198.51.100.1")
	req.Header.Set("X-Real-IP", "198.51.100.2")

	// Since 203.0.113.50 is not in TRUSTED_PROXIES, spoofed headers must be ignored
	ip := getClientIP(req)
	if ip != "203.0.113.50" {
		t.Errorf("getClientIP with untrusted proxy returned %q, want %q", ip, "203.0.113.50")
	}
}

func TestGetClientIP_TrustedProxyRTL(t *testing.T) {
	// Configure trusted proxies with exact IPs and CIDR ranges
	configureTrustedProxies("10.0.0.1, 10.0.0.2, 172.16.0.0/12, 127.0.0.1")

	tests := []struct {
		name       string
		remoteAddr string
		xff        string
		xri        string
		wantIP     string
	}{
		{
			name:       "untrusted direct peer ignores XFF",
			remoteAddr: "198.51.100.99:8080",
			xff:        "1.1.1.1, 2.2.2.2",
			wantIP:     "198.51.100.99",
		},
		{
			name:       "single trusted proxy extracts client IP",
			remoteAddr: "10.0.0.1:443",
			xff:        "203.0.113.195",
			wantIP:     "203.0.113.195",
		},
		{
			name:       "spoofed leftmost IP is ignored via right-to-left traversal",
			remoteAddr: "10.0.0.1:443",
			xff:        "1.1.1.1, 203.0.113.195",
			wantIP:     "203.0.113.195",
		},
		{
			name:       "multi-hop trusted proxies traverses backward past trusted hops",
			remoteAddr: "10.0.0.1:443",
			xff:        "1.1.1.1, 203.0.113.195, 10.0.0.2",
			wantIP:     "203.0.113.195",
		},
		{
			name:       "CIDR-matched proxy (172.16.0.0/12) traverses to client",
			remoteAddr: "172.16.10.5:5000",
			xff:        "8.8.8.8, 198.51.100.44",
			wantIP:     "198.51.100.44",
		},
		{
			name:       "malformed IP entries are skipped",
			remoteAddr: "10.0.0.1:443",
			xff:        "<script>alert(1)</script>, 203.0.113.77",
			wantIP:     "203.0.113.77",
		},
		{
			name:       "unverified X-Real-IP is ignored and socket peer is returned",
			remoteAddr: "10.0.0.1:443",
			xff:        "",
			xri:        "203.0.113.88",
			wantIP:     "10.0.0.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "/test", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}
			if tt.xri != "" {
				req.Header.Set("X-Real-IP", tt.xri)
			}

			got := getClientIP(req)
			if got != tt.wantIP {
				t.Errorf("getClientIP() = %q, want %q", got, tt.wantIP)
			}
		})
	}
}

func TestHandleAuthError_SanitizationAndStatus(t *testing.T) {
	tests := []struct {
		name         string
		err          error
		wantStatus   int
		wantCode     string
		forbidInBody string
	}{
		{
			name: "token revoked returns 401 token_revoked",
			err: &AuthError{
				Code:       AuthErrTokenRevoked,
				HTTPStatus: http.StatusUnauthorized,
				Message:    "Authentication token has been revoked. Please log in again.",
				Internal:   errors.New("firebase_internal_revocation_id_9999_secret_token"),
			},
			wantStatus:   http.StatusUnauthorized,
			wantCode:     "token_revoked",
			forbidInBody: "firebase_internal_revocation_id_9999_secret_token",
		},
		{
			name: "account disabled returns 403 account_disabled",
			err: &AuthError{
				Code:       AuthErrAccountDisabled,
				HTTPStatus: http.StatusForbidden,
				Message:    "Your account has been disabled",
				Internal:   nil,
			},
			wantStatus: http.StatusForbidden,
			wantCode:   "account_disabled",
		},
		{
			name: "transient auth failure returns 503 service_unavailable without internal leak",
			err: &AuthError{
				Code:       AuthErrServiceUnavailable,
				HTTPStatus: http.StatusServiceUnavailable,
				Message:    "Authentication verification service temporarily unavailable",
				Internal:   errors.New("dial tcp 172.217.16.202:443: connect: connection timed out at googleapis.com/auth"),
			},
			wantStatus:   http.StatusServiceUnavailable,
			wantCode:     "service_unavailable",
			forbidInBody: "googleapis.com",
		},
		{
			name: "unclassified error falls back to 401 invalid_token",
			err:  errors.New("some unexpected raw failure"),
			wantStatus: http.StatusUnauthorized,
			wantCode:   "invalid_token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handleAuthError(rec, tt.err)

			if rec.Code != tt.wantStatus {
				t.Errorf("handleAuthError() status = %d, want %d", rec.Code, tt.wantStatus)
			}

			var resp APIErrorResponse
			if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
				t.Fatalf("Failed to decode JSON response: %v", err)
			}

			if resp.Error != tt.wantCode {
				t.Errorf("response error code = %q, want %q", resp.Error, tt.wantCode)
			}

			if tt.forbidInBody != "" && strings.Contains(rec.Body.String(), tt.forbidInBody) {
				t.Errorf("Response body leaked sensitive internal info %q: %s", tt.forbidInBody, rec.Body.String())
			}
		})
	}
}

type mockNetTimeoutError struct{}

func (e *mockNetTimeoutError) Error() string   { return "network i/o timeout" }
func (e *mockNetTimeoutError) Timeout() bool   { return true }
func (e *mockNetTimeoutError) Temporary() bool { return true }

func TestIsTransientAuthError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"context deadline exceeded", context.DeadlineExceeded, true},
		{"context canceled", context.Canceled, true},
		{"net.Error timeout", &mockNetTimeoutError{}, true},
		{"plain string error is NOT transient", errors.New("remote server returned 503 Service Unavailable"), false},
		{"expired token is NOT transient", errors.New("id token has expired"), false},
		{"invalid signature is NOT transient", errors.New("token contains an invalid signature"), false},
		{"nil error", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isTransientAuthError(tt.err)
			if got != tt.want {
				t.Errorf("isTransientAuthError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}
