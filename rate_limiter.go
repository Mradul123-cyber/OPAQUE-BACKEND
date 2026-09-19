package main

import (
	"encoding/json"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	trustedProxyMu     sync.RWMutex
	trustedExactIPs    map[string]bool
	trustedCIDRs       []*net.IPNet
	trustedProxiesOnce sync.Once
)

// initTrustedProxiesFromEnv initializes trusted proxies from TRUSTED_PROXIES environment variable once.
func initTrustedProxiesFromEnv() {
	trustedProxiesOnce.Do(func() {
		configureTrustedProxies(os.Getenv("TRUSTED_PROXIES"))
	})
}

// configureTrustedProxies parses a comma-separated list of IPs and CIDR ranges.
func configureTrustedProxies(env string) {
	trustedProxyMu.Lock()
	defer trustedProxyMu.Unlock()

	trustedExactIPs = make(map[string]bool)
	trustedCIDRs = nil

	if env == "" {
		return
	}

	for _, p := range strings.Split(env, ",") {
		trimmed := strings.TrimSpace(p)
		if trimmed == "" {
			continue
		}
		if strings.Contains(trimmed, "/") {
			_, ipNet, err := net.ParseCIDR(trimmed)
			if err == nil && ipNet != nil {
				trustedCIDRs = append(trustedCIDRs, ipNet)
				continue
			}
		}
		parsed := net.ParseIP(trimmed)
		if parsed != nil {
			trustedExactIPs[parsed.String()] = true
		}
	}
}

// isTrustedProxy checks if an IP belongs to a configured trusted reverse proxy (exact IP or CIDR).
func isTrustedProxy(ipStr string) bool {
	initTrustedProxiesFromEnv()

	parsed := net.ParseIP(strings.TrimSpace(ipStr))
	if parsed == nil {
		return false
	}

	trustedProxyMu.RLock()
	defer trustedProxyMu.RUnlock()

	if trustedExactIPs[parsed.String()] {
		return true
	}

	for _, cidr := range trustedCIDRs {
		if cidr.Contains(parsed) {
			return true
		}
	}

	return false
}

// clientBucket tracks rate limit tokens for a single client (IP or UID).
type clientBucket struct {
	tokens     float64
	lastRefill time.Time
}

// IPRateLimiter is an in-memory token-bucket rate limiter.
type IPRateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*clientBucket
	rate    float64 // tokens per second
	burst   float64 // max bucket capacity
}

// NewIPRateLimiter creates a new rate limiter with the specified rate and burst.
func NewIPRateLimiter(ratePerSec float64, burst float64) *IPRateLimiter {
	limiter := &IPRateLimiter{
		buckets: make(map[string]*clientBucket),
		rate:    ratePerSec,
		burst:   burst,
	}

	// Periodic cleanup of idle buckets every 5 minutes
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		for range ticker.C {
			limiter.mu.Lock()
			now := time.Now()
			for key, b := range limiter.buckets {
				// Remove buckets idle for more than 10 minutes
				if now.Sub(b.lastRefill) > 10*time.Minute {
					delete(limiter.buckets, key)
				}
			}
			limiter.mu.Unlock()
		}
	}()

	return limiter
}

// Allow checks whether a request from the given key is permitted.
func (l *IPRateLimiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	b, exists := l.buckets[key]
	if !exists {
		l.buckets[key] = &clientBucket{
			tokens:     l.burst - 1,
			lastRefill: now,
		}
		return true
	}

	// Refill tokens based on elapsed time
	elapsed := now.Sub(b.lastRefill).Seconds()
	b.lastRefill = now
	b.tokens += elapsed * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}

	if b.tokens >= 1.0 {
		b.tokens -= 1.0
		return true
	}

	return false
}

// getClientIP extracts client IP address.
// Forwarded headers (X-Forwarded-For, X-Real-IP) are ONLY trusted if the direct connection
// originates from an explicitly configured trusted proxy (via TRUSTED_PROXIES).
// When trusted, X-Forwarded-For is traversed right-to-left (from immediate peer backward)
// to prevent spoofing behind append-style proxies.
func getClientIP(r *http.Request) string {
	remoteHost, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		remoteHost = r.RemoteAddr
	}
	remoteHost = strings.TrimSpace(remoteHost)

	// If immediate peer is NOT a trusted proxy, completely ignore forwarded headers
	if !isTrustedProxy(remoteHost) {
		return remoteHost
	}

	// Traverse X-Forwarded-For right-to-left to find the first untrusted IP
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		parts := strings.Split(xff, ",")
		for i := len(parts) - 1; i >= 0; i-- {
			candidate := strings.TrimSpace(parts[i])
			if candidate == "" {
				continue
			}
			parsed := net.ParseIP(candidate)
			if parsed == nil {
				// Discard malformed/non-IP entries
				continue
			}
			if !isTrustedProxy(candidate) {
				// First untrusted IP from the right is the genuine client IP
				return parsed.String()
			}
		}
		// If all IPs in the XFF chain were trusted proxies, return the leftmost valid IP
		for i := 0; i < len(parts); i++ {
			candidate := strings.TrimSpace(parts[i])
			parsed := net.ParseIP(candidate)
			if parsed != nil {
				return parsed.String()
			}
		}
	}

	return remoteHost
}

// RateLimitMiddleware wraps a handler func with rate limiting.
func RateLimitMiddleware(limiter *IPRateLimiter, endpointName string) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			clientIP := getClientIP(r)
			if !limiter.Allow(clientIP) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				json.NewEncoder(w).Encode(APIErrorResponse{
					Error:   "rate_limited",
					Message: "Too many requests. Please slow down and try again shortly.",
				})
				return
			}
			next(w, r)
		}
	}
}
