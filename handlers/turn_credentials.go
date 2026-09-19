package handlers

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

// TURNCredentials represents the TURN server configuration
type TURNCredentials struct {
	Username    string                   `json:"username"`
	Credential  string                   `json:"credential"`
	TTL         int                      `json:"ttl"` // Time to live in seconds
	IceServers  []map[string]interface{} `json:"ice_servers"`
}

// GetTURNCredentials generates time-limited TURN credentials
func GetTURNCredentials(w http.ResponseWriter, r *http.Request) {
	// Enable CORS
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Get TURN secret from environment variable
	turnSecret := os.Getenv("TURN_SECRET")
	if turnSecret == "" {
		turnSecret = "zarq_secret_key_12345" // Fallback for dev
	}

	turnServerURL := os.Getenv("TURN_SERVER_URL")
	if turnServerURL == "" {
		turnServerURL = "zarqmessenger.com"
	}

	turnServerIP := os.Getenv("TURN_SERVER_IP")
	if turnServerIP == "" {
		turnServerIP = "64.227.191.148"
	}

	// Generate time-limited credentials (24 hours)
	ttl := 86400
	timestamp := time.Now().Unix() + int64(ttl)
	username := fmt.Sprintf("%d:zarquser", timestamp)

	// Generate HMAC-SHA1 credential
	mac := hmac.New(sha1.New, []byte(turnSecret))
	mac.Write([]byte(username))
	credential := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	// Build ICE servers configuration
	iceServers := []map[string]interface{}{
		{"urls": "stun:stun.l.google.com:19302"},
		{"urls": "stun:stun1.l.google.com:19302"},
		{
			"urls": []string{
				fmt.Sprintf("turn:%s:3478", turnServerURL),
				fmt.Sprintf("turn:%s:3478?transport=tcp", turnServerURL),
			},
			"username":   username,
			"credential": credential,
		},
		{
			"urls": []string{
				fmt.Sprintf("turn:%s:3478", turnServerIP),
				fmt.Sprintf("turn:%s:3478?transport=tcp", turnServerIP),
			},
			"username":   username,
			"credential": credential,
		},
	}

	response := TURNCredentials{
		Username:   username,
		Credential: credential,
		TTL:        ttl,
		IceServers: iceServers,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}
