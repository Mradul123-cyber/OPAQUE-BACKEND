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

// GetTURNCredentials generates time-limited TURN credentials (legacy/default caller)
func GetTURNCredentials(w http.ResponseWriter, r *http.Request) {
	GetTURNCredentialsForUser(w, r, "zarquser")
}

// GetTURNCredentialsForUser generates time-limited TURN credentials for an authenticated user
func GetTURNCredentialsForUser(w http.ResponseWriter, r *http.Request, userUID string) {
	// Enable CORS
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Default public Google STUN servers (always available for direct P2P connections)
	iceServers := []map[string]interface{}{
		{"urls": "stun:stun.l.google.com:19302"},
		{"urls": "stun:stun1.l.google.com:19302"},
	}

	// Read TURN server configuration from environment variables
	turnSecret := os.Getenv("TURN_SECRET")
	turnServerURL := os.Getenv("TURN_SERVER_URL")
	turnServerIP := os.Getenv("TURN_SERVER_IP")

	// If TURN server is not configured in .env (e.g. server is shut down or in development),
	// return STUN servers gracefully so direct P2P calls can still be attempted.
	if turnSecret == "" || (turnServerURL == "" && turnServerIP == "") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(TURNCredentials{
			Username:   "",
			Credential: "",
			TTL:        0,
			IceServers: iceServers,
		})
		return
	}

	// Generate time-limited credentials (24 hours)
	ttl := 86400
	timestamp := time.Now().Unix() + int64(ttl)
	username := fmt.Sprintf("%d:%s", timestamp, userUID)

	// Generate HMAC-SHA1 credential using the configured TURN_SECRET
	mac := hmac.New(sha1.New, []byte(turnSecret))
	mac.Write([]byte(username))
	credential := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	// Build ICE servers configuration
	if turnServerURL != "" {
		iceServers = append(iceServers, map[string]interface{}{
			"urls": []string{
				fmt.Sprintf("turn:%s:3478", turnServerURL),
				fmt.Sprintf("turn:%s:3478?transport=tcp", turnServerURL),
			},
			"username":   username,
			"credential": credential,
		})
	}

	if turnServerIP != "" {
		iceServers = append(iceServers, map[string]interface{}{
			"urls": []string{
				fmt.Sprintf("turn:%s:3478", turnServerIP),
				fmt.Sprintf("turn:%s:3478?transport=tcp", turnServerIP),
			},
			"username":   username,
			"credential": credential,
		})
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
