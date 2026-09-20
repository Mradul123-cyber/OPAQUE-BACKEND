// main.go
package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"zarq-messenger/handlers"

	"firebase.google.com/go/v4/auth"
	"firebase.google.com/go/v4/errorutils"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"github.com/lib/pq"
)

var globalHub *Hub
var db *sql.DB

const MAX_GROUP_MEMBERS = 100
const MAX_FRIENDS = 500

var (
	usernameCheckLimiter = NewIPRateLimiter(0.5, 30.0) // 30 req/min burst
	profileCreateLimiter = NewIPRateLimiter(0.1, 5.0)  // 5 req/min burst
	usernameRegex        = regexp.MustCompile(`^[a-zA-Z0-9_]{3,30}$`)
	reservedUsernames    = map[string]bool{
		"admin": true, "administrator": true, "root": true,
		"system": true, "support": true, "opaque": true,
		"zarq": true, "anonymous": true, "official": true,
	}
)

// sendJSONError writes a consistent JSON error response.
func sendJSONError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(APIErrorResponse{
		Error:   code,
		Message: message,
	})
}

// validateUsername ensures usernames conform to security and formatting constraints.
func validateUsername(username string) error {
	trimmed := strings.TrimSpace(username)
	if len(trimmed) < 3 || len(trimmed) > 30 {
		return fmt.Errorf("username must be between 3 and 30 characters")
	}
	if !usernameRegex.MatchString(trimmed) {
		return fmt.Errorf("username can only contain letters, numbers, and underscores")
	}
	if reservedUsernames[strings.ToLower(trimmed)] {
		return fmt.Errorf("username is reserved and cannot be used")
	}
	return nil
}

// AuthErrorCode represents standardized authentication error codes returned to clients.
type AuthErrorCode string

const (
	AuthErrInvalidToken       AuthErrorCode = "invalid_token"
	AuthErrTokenRevoked       AuthErrorCode = "token_revoked"
	AuthErrAccountDisabled    AuthErrorCode = "account_disabled"
	AuthErrServiceUnavailable AuthErrorCode = "service_unavailable"
)

// AuthError is a typed error containing a client-safe code, HTTP status, sanitized message,
// and underlying internal error (retained strictly for server-side diagnostic logging).
type AuthError struct {
	Code       AuthErrorCode
	HTTPStatus int
	Message    string // Sanitized, user-facing error message (never leaks internal details)
	Internal   error  // Internal error preserved for server logs
}

func (e *AuthError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func (e *AuthError) Unwrap() error {
	return e.Internal
}

// isTransientAuthError determines if an error represents an infrastructure outage or transient failure
// using structured SDK, context, and network error classification.
func isTransientAuthError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}
	if errorutils.IsUnavailable(err) || errorutils.IsDeadlineExceeded(err) || errorutils.IsInternal(err) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && (netErr.Timeout() || netErr.Temporary()) {
		return true
	}
	return false
}

// handleAuthError maps typed AuthErrors to standardized HTTP responses, failing closed
// and never exposing raw internal stack traces or Firebase SDK error strings to clients.
func handleAuthError(w http.ResponseWriter, err error) {
	var authErr *AuthError
	if errors.As(err, &authErr) {
		if authErr.Internal != nil {
			log.Printf("Authentication error [%s] (HTTP %d): %v", authErr.Code, authErr.HTTPStatus, authErr.Internal)
		}
		sendJSONError(w, authErr.HTTPStatus, string(authErr.Code), authErr.Message)
		return
	}

	log.Printf("Unclassified authentication error: %v", err)
	sendJSONError(w, http.StatusUnauthorized, string(AuthErrInvalidToken), "Invalid authentication credentials")
}

// verifyFirebaseTokenStrict verifies the Firebase ID token with strict revocation and disabled checking.
// It fails closed: revoked tokens are rejected immediately. Infrastructure outages return service_unavailable (503).
func verifyFirebaseTokenStrict(ctx context.Context, tokenStr string) (*auth.Token, *auth.UserRecord, error) {
	if firebaseAuth == nil {
		return nil, nil, &AuthError{
			Code:       AuthErrServiceUnavailable,
			HTTPStatus: http.StatusServiceUnavailable,
			Message:    "Authentication verification service temporarily unavailable",
			Internal:   errors.New("firebase auth not initialized"),
		}
	}

	token, err := firebaseAuth.VerifyIDTokenAndCheckRevoked(ctx, tokenStr)
	if err != nil {
		// 1. Revoked token check
		if auth.IsIDTokenRevoked(err) {
			return nil, nil, &AuthError{
				Code:       AuthErrTokenRevoked,
				HTTPStatus: http.StatusUnauthorized,
				Message:    "Authentication token has been revoked. Please log in again.",
				Internal:   err,
			}
		}

		// 2. Disabled user check: must precede IsIDTokenInvalid because Firebase documents that IsUserDisabled also satisfies IsIDTokenInvalid
		if auth.IsUserDisabled(err) {
			return nil, nil, &AuthError{
				Code:       AuthErrAccountDisabled,
				HTTPStatus: http.StatusForbidden,
				Message:    "Your account has been disabled",
				Internal:   err,
			}
		}

		// 3. Invalid or expired token check
		if auth.IsIDTokenInvalid(err) {
			return nil, nil, &AuthError{
				Code:       AuthErrInvalidToken,
				HTTPStatus: http.StatusUnauthorized,
				Message:    "Authentication token is invalid or expired",
				Internal:   err,
			}
		}

		// 4. Any transient infrastructure/network failure or unclassified verification-service failure returns 503 service_unavailable
		return nil, nil, &AuthError{
			Code:       AuthErrServiceUnavailable,
			HTTPStatus: http.StatusServiceUnavailable,
			Message:    "Authentication verification service temporarily unavailable",
			Internal:   err,
		}
	}

	userRecord, err := firebaseAuth.GetUser(ctx, token.UID)
	if err != nil {
		if auth.IsUserNotFound(err) {
			return nil, nil, &AuthError{
				Code:       AuthErrInvalidToken,
				HTTPStatus: http.StatusUnauthorized,
				Message:    "User account not found",
				Internal:   err,
			}
		}
		if auth.IsUserDisabled(err) {
			return nil, nil, &AuthError{
				Code:       AuthErrAccountDisabled,
				HTTPStatus: http.StatusForbidden,
				Message:    "Your account has been disabled",
				Internal:   err,
			}
		}
		return nil, nil, &AuthError{
			Code:       AuthErrServiceUnavailable,
			HTTPStatus: http.StatusServiceUnavailable,
			Message:    "Authentication service lookup temporarily unavailable",
			Internal:   err,
		}
	}

	if userRecord.Disabled {
		return nil, nil, &AuthError{
			Code:       AuthErrAccountDisabled,
			HTTPStatus: http.StatusForbidden,
			Message:    "Your account has been disabled",
			Internal:   nil,
		}
	}

	return token, userRecord, nil
}

// getTrustedIdentity verifies the Firebase ID token and fetches live UserRecord.
func getTrustedIdentity(r *http.Request) (*TrustedIdentity, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, &AuthError{
			Code:       AuthErrInvalidToken,
			HTTPStatus: http.StatusUnauthorized,
			Message:    "Authorization header required",
			Internal:   errors.New("missing Authorization header"),
		}
	}

	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
	token, userRecord, err := verifyFirebaseTokenStrict(r.Context(), tokenStr)
	if err != nil {
		return nil, err
	}

	provider := token.Firebase.SignInProvider
	if provider == "" && len(userRecord.ProviderUserInfo) > 0 {
		provider = userRecord.ProviderUserInfo[0].ProviderID
	}

	return &TrustedIdentity{
		UID:            userRecord.UID,
		PhoneNumber:    userRecord.PhoneNumber,
		Email:          userRecord.Email,
		EmailVerified:  userRecord.EmailVerified,
		Disabled:       userRecord.Disabled,
		SignInProvider: provider,
	}, nil
}

// getVerifiedToken verifies token and returns UID and username for authenticated endpoints.
func getVerifiedToken(r *http.Request) (*auth.Token, string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, "", &AuthError{
			Code:       AuthErrInvalidToken,
			HTTPStatus: http.StatusUnauthorized,
			Message:    "Authorization header required",
			Internal:   errors.New("missing Authorization header"),
		}
	}

	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
	token, userRecord, err := verifyFirebaseTokenStrict(r.Context(), tokenStr)
	if err != nil {
		return nil, "", err
	}

	username := userRecord.DisplayName
	if username == "" {
		username = userRecord.Email
	}

	return token, username, nil
}

func getVerifiedTokenForWs(r *http.Request) (*auth.Token, error) {
	tokenStr := r.URL.Query().Get("token")
	if tokenStr == "" {
		return nil, &AuthError{
			Code:       AuthErrInvalidToken,
			HTTPStatus: http.StatusUnauthorized,
			Message:    "Token query parameter required",
			Internal:   errors.New("missing token query parameter"),
		}
	}
	token, _, err := verifyFirebaseTokenStrict(r.Context(), tokenStr)
	if err != nil {
		return nil, err
	}
	return token, nil
}

func checkUsernameAvailabilityHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var payload struct {
		Username string `json:"username"`
	}

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		sendJSONError(w, http.StatusBadRequest, "invalid_body", "Invalid request body")
		return
	}

	trimmed := strings.TrimSpace(payload.Username)
	if trimmed == "" {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"available": false,
			"reason":    "Username cannot be empty",
		})
		return
	}

	if err := validateUsername(trimmed); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"available": false,
			"reason":    err.Error(),
		})
		return
	}

	// Check if username exists in database case-insensitively
	var exists bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM profiles WHERE LOWER(username) = LOWER($1))", trimmed).Scan(&exists)
	if err != nil {
		log.Printf("Error checking username availability: %v", err)
		sendJSONError(w, http.StatusInternalServerError, "server_error", "Failed to check username availability")
		return
	}

	if exists {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"available": false,
			"reason":    "Username is already taken",
		})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"available": true,
	})
}

// fetchExistingProfile retrieves an existing profile by Firebase UID, returning nil if not found.
// Database errors are returned so callers can distinguish non-existence from infrastructure outages.
func fetchExistingProfile(ctx context.Context, uid, phoneNumber, email string) (*ProfileResponse, error) {
	var username string
	var displayName, avatar, phoneHash sql.NullString
	err := db.QueryRowContext(
		ctx,
		"SELECT username, display_name, profile_avatar_url, phone_hash FROM profiles WHERE firebase_uid = $1",
		uid,
	).Scan(&username, &displayName, &avatar, &phoneHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	return &ProfileResponse{
		Status:      "existing",
		Message:     "Profile already exists",
		UID:         uid,
		Username:    username,
		DisplayName: displayName.String,
		AvatarURL:   avatar.String,
		PhoneNumber: phoneNumber,
		Email:       email,
	}, nil
}

func createProfileHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	identity, err := getTrustedIdentity(r)
	if err != nil {
		handleAuthError(w, err)
		return
	}

	// Rate limit by verified UID (prevents distributed IP attacks against a single user account)
	if !profileCreateLimiter.Allow("uid:" + identity.UID) {
		sendJSONError(w, http.StatusTooManyRequests, "rate_limited", "Too many registration attempts for this account. Please wait a moment.")
		return
	}

	// Ensure user has at least one verified channel
	hasVerifiedPhone := identity.PhoneNumber != ""
	hasVerifiedEmail := identity.Email != "" && identity.EmailVerified
	isGoogleOAuth := identity.SignInProvider == "google.com"

	if !hasVerifiedPhone && !hasVerifiedEmail && !isGoogleOAuth {
		sendJSONError(w, http.StatusForbidden, "unverified_account", "Account must have verified phone number or verified email")
		return
	}

	// 1. Idempotent Resume: If profile already exists for this UID, return it without modifying it
	existing, err := fetchExistingProfile(r.Context(), identity.UID, identity.PhoneNumber, identity.Email)
	if err != nil {
		log.Printf("createProfileHandler: fetchExistingProfile error: %v", err)
		sendJSONError(w, http.StatusInternalServerError, "server_error", "Database error checking existing profile")
		return
	}
	if existing != nil {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(existing)
		return
	}

	var p ProfilePayload
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		sendJSONError(w, http.StatusBadRequest, "invalid_body", "Invalid request body")
		return
	}

	username := strings.TrimSpace(p.Username)
	if err := validateUsername(username); err != nil {
		sendJSONError(w, http.StatusBadRequest, "invalid_username", err.Error())
		return
	}

	displayName := strings.TrimSpace(p.DisplayName)
	if displayName == "" {
		displayName = username
	}
	// Truncate by Unicode characters (runes), not slicing raw bytes
	displayRunes := []rune(displayName)
	if len(displayRunes) > 100 {
		displayName = string(displayRunes[:100])
	}

	// 2. Prepare phone_hash: derive strictly from trusted Firebase identity
	var phoneHash *string
	if identity.PhoneNumber != "" {
		hasher := sha256.New()
		hasher.Write([]byte(identity.PhoneNumber))
		h := hex.EncodeToString(hasher.Sum(nil))
		phoneHash = &h
	}

	// 3. Atomically insert in a transaction to guarantee uniqueness and reconcile races
	tx, err := db.BeginTx(r.Context(), nil)
	if err != nil {
		log.Printf("createProfileHandler: tx begin error: %v", err)
		sendJSONError(w, http.StatusInternalServerError, "server_error", "Internal server error")
		return
	}
	defer tx.Rollback()

	// Check if username is taken (case-insensitive), reconciling if taken by same UID or if UID completed concurrently
	var usernameOwnerUID string
	err = tx.QueryRowContext(r.Context(), "SELECT firebase_uid FROM profiles WHERE LOWER(username) = LOWER($1)", username).Scan(&usernameOwnerUID)
	if err == nil {
		_ = tx.Rollback()
		// Reconcile: If this UID already completed registration concurrently (e.g. from simultaneous request)
		existing, fetchErr := fetchExistingProfile(r.Context(), identity.UID, identity.PhoneNumber, identity.Email)
		if fetchErr != nil {
			log.Printf("createProfileHandler: username precheck reconcile error: %v", fetchErr)
			sendJSONError(w, http.StatusInternalServerError, "server_error", "Database error checking profile")
			return
		}
		if existing != nil {
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(existing)
			return
		}
		sendJSONError(w, http.StatusConflict, "username_taken", "This username is already taken")
		return
	} else if !errors.Is(err, sql.ErrNoRows) {
		log.Printf("createProfileHandler: username check error: %v", err)
		sendJSONError(w, http.StatusInternalServerError, "server_error", "Database error checking username")
		return
	}

	// If phone exists, check if phone_hash is already bound, reconciling if bound to same UID or if UID completed concurrently
	if phoneHash != nil {
		var phoneOwnerUID string
		err = tx.QueryRowContext(r.Context(), "SELECT firebase_uid FROM profiles WHERE phone_hash = $1", *phoneHash).Scan(&phoneOwnerUID)
		if err == nil {
			_ = tx.Rollback()
			// Reconcile: If this UID already completed registration concurrently
			existing, fetchErr := fetchExistingProfile(r.Context(), identity.UID, identity.PhoneNumber, identity.Email)
			if fetchErr != nil {
				log.Printf("createProfileHandler: phone precheck reconcile error: %v", fetchErr)
				sendJSONError(w, http.StatusInternalServerError, "server_error", "Database error checking profile")
				return
			}
			if existing != nil {
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(existing)
				return
			}
			sendJSONError(w, http.StatusConflict, "phone_taken", "This phone number is already registered to another account")
			return
		} else if !errors.Is(err, sql.ErrNoRows) {
			log.Printf("createProfileHandler: phone check error: %v", err)
			sendJSONError(w, http.StatusInternalServerError, "server_error", "Database error checking phone")
			return
		}
	}

	// Perform insert
	insertQuery := `INSERT INTO profiles (firebase_uid, username, phone_hash, display_name) VALUES ($1, $2, $3, $4)`
	_, err = tx.ExecContext(r.Context(), insertQuery, identity.UID, username, phoneHash, displayName)
	if err != nil {
		_ = tx.Rollback()
		if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == "23505" {
			// Reconcile: If this UID now exists in DB, concurrent creation succeeded!
			existing, fetchErr := fetchExistingProfile(r.Context(), identity.UID, identity.PhoneNumber, identity.Email)
			if fetchErr != nil {
				log.Printf("createProfileHandler: insert conflict reconcile error: %v", fetchErr)
				sendJSONError(w, http.StatusInternalServerError, "server_error", "Database error checking profile")
				return
			}
			if existing != nil {
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(existing)
				return
			}
			if strings.Contains(pqErr.Constraint, "username") {
				sendJSONError(w, http.StatusConflict, "username_taken", "This username was just claimed by another user")
				return
			} else if strings.Contains(pqErr.Constraint, "phone") {
				sendJSONError(w, http.StatusConflict, "phone_taken", "This phone number was just registered by another user")
				return
			}
		}
		log.Printf("createProfileHandler: insert failed: %v", err)
		sendJSONError(w, http.StatusInternalServerError, "server_error", "Failed to create profile")
		return
	}

	if err := tx.Commit(); err != nil {
		log.Printf("createProfileHandler: tx commit failed: %v", err)
		existing, fetchErr := fetchExistingProfile(r.Context(), identity.UID, identity.PhoneNumber, identity.Email)
		if fetchErr != nil {
			log.Printf("createProfileHandler: commit reconcile error: %v", fetchErr)
			sendJSONError(w, http.StatusInternalServerError, "server_error", "Failed to commit profile")
			return
		}
		if existing != nil {
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(existing)
			return
		}
		sendJSONError(w, http.StatusInternalServerError, "server_error", "Failed to commit profile")
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(ProfileResponse{
		Status:      "created",
		Message:     "Profile created successfully",
		UID:         identity.UID,
		Username:    username,
		DisplayName: displayName,
		PhoneNumber: identity.PhoneNumber,
		Email:       identity.Email,
	})
	log.Printf("✅ Profile created: username=%s, UID=%s, hasPhone=%v", username, identity.UID, phoneHash != nil)
}

func updateAvatarHandler(w http.ResponseWriter, r *http.Request) {
	token, _, err := getVerifiedToken(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	uid := token.UID

	var payload struct {
		AvatarURL string `json:"avatarUrl"`
	}

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if payload.AvatarURL == "" {
		http.Error(w, "avatarUrl is required", http.StatusBadRequest)
		return
	}

	sqlStatement := `UPDATE profiles SET profile_avatar_url = $1 WHERE firebase_uid = $2`
	res, err := db.Exec(sqlStatement, payload.AvatarURL, uid)
	if err != nil {
		log.Printf("Failed to update avatar URL in DB for user %s: %v", uid, err)
		http.Error(w, "Database update failed", http.StatusInternalServerError)
		return
	}

	count, err := res.RowsAffected()
	if err != nil {
		log.Printf("Failed to get rows affected for user %s: %v", uid, err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	if count == 0 {
		http.Error(w, "User profile not found", http.StatusNotFound)
		return
	}
	
	params := (&auth.UserToUpdate{}).PhotoURL(payload.AvatarURL)
	_, err = firebaseAuth.UpdateUser(context.Background(), uid, params)
	if err != nil {
		log.Printf("Warning: Failed to update Firebase Auth PhotoURL for user %s: %v", uid, err)
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Avatar updated successfully"})
	log.Printf("Avatar updated for user: %s", uid)
}

// validateAvatarPrivacy ensures the setting is one of 'everyone', 'contacts', or 'nobody'.
func validateAvatarPrivacy(setting string) (string, error) {
	s := strings.ToLower(strings.TrimSpace(setting))
	if s != "everyone" && s != "contacts" && s != "nobody" {
		return "", fmt.Errorf("avatar privacy must be 'everyone', 'contacts', or 'nobody'")
	}
	return s, nil
}

func updateAvatarPrivacyHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	token, _, err := getVerifiedToken(r)
	if err != nil {
		sendJSONError(w, http.StatusUnauthorized, "invalid_token", err.Error())
		return
	}
	uid := token.UID

	var payload UpdatePrivacyPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		sendJSONError(w, http.StatusBadRequest, "invalid_body", "Invalid request body")
		return
	}

	setting, err := validateAvatarPrivacy(payload.AvatarPrivacy)
	if err != nil {
		sendJSONError(w, http.StatusBadRequest, "invalid_privacy_setting", err.Error())
		return
	}

	_, err = db.Exec("UPDATE profiles SET avatar_privacy = $1 WHERE firebase_uid = $2", setting, uid)
	if err != nil {
		log.Printf("updateAvatarPrivacyHandler: DB update failed for %s: %v", uid, err)
		sendJSONError(w, http.StatusInternalServerError, "server_error", "Failed to update avatar privacy")
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":        "success",
		"message":       "Avatar privacy updated successfully",
		"avatarPrivacy": setting,
	})
	log.Printf("Updated avatar privacy to %s for user %s", setting, uid)
}

func updateDisplayNameHandler(hub *Hub, w http.ResponseWriter, r *http.Request) {
	token, oldUsername, err := getVerifiedToken(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	uid := token.UID

	var payload struct {
		NewName string `json:"newName"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	newName := strings.TrimSpace(payload.NewName)
	if newName == "" || len(newName) > 50 {
		http.Error(w, "New name cannot be empty and must be less than 50 characters", http.StatusBadRequest)
		return
	}

	tx, err := db.Begin()
	if err != nil {
		http.Error(w, "Failed to start transaction", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	_, err = tx.Exec("UPDATE profiles SET username = $1 WHERE firebase_uid = $2", newName, uid)
	if err != nil {
		if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == "23505" {
			http.Error(w, "This username is already taken.", http.StatusConflict)
			return
		}
		http.Error(w, "Failed to update profile in database", http.StatusInternalServerError)
		return
	}

	params := (&auth.UserToUpdate{}).DisplayName(newName)
	_, err = firebaseAuth.UpdateUser(context.Background(), uid, params)
	if err != nil {
		http.Error(w, "Failed to update Firebase user", http.StatusInternalServerError)
		return
	}

	if err := tx.Commit(); err != nil {
		http.Error(w, "Failed to commit transaction", http.StatusInternalServerError)
		return
	}

	updatePayload := map[string]string{"type": "profile_update"}
	updateBytes, _ := json.Marshal(updatePayload)
	hub.broadcast <- HubMessage{message: updateBytes, sender: nil}

	updateUsernameMessage := map[string]string{
		"oldUsername": oldUsername,
		"newUsername": newName,
	}
	hub.updateUsername <- updateUsernameMessage

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Display name updated successfully"})
	log.Printf("Username updated for UID %s from '%s' to '%s'", uid, oldUsername, newName)
}

func updateUserDisplayNameHandler(w http.ResponseWriter, r *http.Request) {
	token, _, err := getVerifiedToken(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	uid := token.UID

	var payload struct {
		DisplayName string `json:"displayName"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	displayName := strings.TrimSpace(payload.DisplayName)
	if displayName == "" || len(displayName) > 100 {
		http.Error(w, "Display name cannot be empty and must be less than 100 characters", http.StatusBadRequest)
		return
	}

	_, err = db.Exec("UPDATE profiles SET display_name = $1 WHERE firebase_uid = $2", displayName, uid)
	if err != nil {
		log.Printf("Failed to update display_name for UID %s: %v", uid, err)
		http.Error(w, "Failed to update display name", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Display name updated successfully"})
	log.Printf("Display name updated for UID %s to '%s'", uid, displayName)
}

func findFriendsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	token, _, err := getVerifiedToken(r)
	if err != nil {
		sendJSONError(w, http.StatusUnauthorized, "unauthorized", err.Error())
		return
	}
	currentUserUID := token.UID

	var hashedContacts []string
	if err := json.NewDecoder(r.Body).Decode(&hashedContacts); err != nil {
		sendJSONError(w, http.StatusBadRequest, "invalid_body", "Invalid request body")
		return
	}

	// Filter out invalid/empty hashes: only 64-character SHA-256 hex strings
	var validHashes []string
	for _, h := range hashedContacts {
		trimmed := strings.TrimSpace(h)
		if len(trimmed) == 64 {
			validHashes = append(validHashes, trimmed)
		}
	}

	if len(validHashes) == 0 {
		json.NewEncoder(w).Encode([]FriendInfo{})
		return
	}

	query := `
		SELECT p.username, 
		       CASE 
		           WHEN p.avatar_privacy = 'nobody' THEN NULL
		           WHEN p.avatar_privacy = 'contacts' AND NOT EXISTS (
		               SELECT 1 FROM friendships f 
		               WHERE ((f.user_a_uid = p.firebase_uid AND f.user_b_uid = $2) OR (f.user_a_uid = $2 AND f.user_b_uid = p.firebase_uid))
		                 AND f.status = 'accepted'
		           ) THEN NULL
		           ELSE p.profile_avatar_url 
		       END AS filtered_avatar_url,
		       p.display_name, 
		       p.phone_hash 
		FROM profiles p 
		WHERE p.phone_hash IS NOT NULL AND p.phone_hash = ANY($1)
	`
	rows, err := db.Query(query, pq.Array(validHashes), currentUserUID)
	if err != nil {
		log.Printf("findFriendsHandler: DB query error: %v", err)
		sendJSONError(w, http.StatusInternalServerError, "server_error", "Database query failed")
		return
	}
	defer rows.Close()

	foundUsers := make([]FriendInfo, 0)
	for rows.Next() {
		var user FriendInfo
		var avatarURL sql.NullString
		var displayName sql.NullString
		var phoneHash sql.NullString

		if err := rows.Scan(&user.Username, &avatarURL, &displayName, &phoneHash); err != nil {
			log.Printf("findFriendsHandler: scan error: %v", err)
			continue
		}
		if avatarURL.Valid {
			user.AvatarURL = avatarURL.String
		}
		if displayName.Valid {
			user.DisplayName = displayName.String
		}
		if phoneHash.Valid {
			user.PhoneHash = phoneHash.String
		}
		foundUsers = append(foundUsers, user)
	}

	json.NewEncoder(w).Encode(foundUsers)
}

func searchUsersHandler(w http.ResponseWriter, r *http.Request) {
	token, _, err := getVerifiedToken(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	currentUserUID := token.UID
	query := r.URL.Query().Get("q")
	if query == "" {
		http.Error(w, "Search query 'q' is required", http.StatusBadRequest)
		return
	}

	// Search by username only, but return display_name for display with avatar privacy filter
	sqlStatement := `
		SELECT p.username, 
		       CASE 
		           WHEN p.avatar_privacy = 'nobody' THEN NULL
		           WHEN p.avatar_privacy = 'contacts' AND NOT EXISTS (
		               SELECT 1 FROM friendships f 
		               WHERE ((f.user_a_uid = p.firebase_uid AND f.user_b_uid = $2) OR (f.user_a_uid = $2 AND f.user_b_uid = p.firebase_uid))
		                 AND f.status = 'accepted'
		           ) THEN NULL
		           ELSE p.profile_avatar_url 
		       END AS filtered_avatar_url,
		       p.display_name 
		FROM profiles p 
		WHERE p.username ILIKE $1 AND p.firebase_uid != $2 
		LIMIT 10
	`
	rows, err := db.Query(sqlStatement, "%"+query+"%", currentUserUID)
	if err != nil {
		http.Error(w, "Database query failed", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	foundUsers := []FriendInfo{}
	for rows.Next() {
		var user FriendInfo
		var avatarURL sql.NullString
		var displayName sql.NullString
		if err := rows.Scan(&user.Username, &avatarURL, &displayName); err != nil {
			log.Printf("Error scanning user search result: %v", err)
			continue
		}
		if avatarURL.Valid {
			user.AvatarURL = avatarURL.String
		}
		if displayName.Valid {
			user.DisplayName = displayName.String
		}
		foundUsers = append(foundUsers, user)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(foundUsers)
}

func sendFriendRequestHandler(w http.ResponseWriter, r *http.Request) {
	senderToken, _, err := getVerifiedToken(r)
	if err != nil { http.Error(w, err.Error(), http.StatusUnauthorized); return }
	senderUID := senderToken.UID
	var p FriendRequestPayload
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil { http.Error(w, "Invalid request body", http.StatusBadRequest); return }
	targetUsername := p.TargetUsername
	var targetUID string
	err = db.QueryRow("SELECT firebase_uid FROM profiles WHERE username = $1", targetUsername).Scan(&targetUID)
	if err != nil { http.Error(w, "User not found", http.StatusNotFound); return }
	if senderUID == targetUID { http.Error(w, "You cannot send a friend request to yourself.", http.StatusBadRequest); return }

	if senderUID == targetUID { http.Error(w, "You cannot send a friend request to yourself.", http.StatusBadRequest); return }

  // Check friends limit
  var friendCount int
  err = db.QueryRow("SELECT COUNT(*) FROM friendships WHERE (user_a_uid = $1 OR user_b_uid = $1) AND status = 'accepted'",
  senderUID).Scan(&friendCount)
  if err != nil {
        http.Error(w, "Failed to check friend count", http.StatusInternalServerError)
        return
  }
  if friendCount >= MAX_FRIENDS {
        http.Error(w, fmt.Sprintf("You have reached the maximum friends limit (%d)", MAX_FRIENDS), http.StatusBadRequest)
        return
  }

	userA := senderUID
	userB := targetUID
	if userA > userB { userA, userB = userB, userA }
	sqlStatement := `INSERT INTO friendships (user_a_uid, user_b_uid, requester_uid, status) VALUES ($1, $2, $3, 'pending')`
	if _, err = db.Exec(sqlStatement, userA, userB, senderUID); err != nil {
		http.Error(w, "Friend request already sent or already friends", http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, "Friend request sent to %s", targetUsername)
	log.Printf("Friend request sent from %s to %s", senderUID, targetUID)
}

func getFriendRequestsHandler(w http.ResponseWriter, r *http.Request) {
    token, _, err := getVerifiedToken(r)
    if err != nil {
        http.Error(w, err.Error(), http.StatusUnauthorized)
        return
    }
    currentUserUID := token.UID

    // Query with display_name and avatar privacy filter
    query := `
        SELECT p.username, 
               CASE WHEN p.avatar_privacy = 'everyone' THEN p.profile_avatar_url ELSE NULL END AS filtered_avatar_url, 
               p.display_name
        FROM profiles p
        JOIN friendships f ON p.firebase_uid = f.requester_uid
        WHERE (f.user_a_uid = $1 OR f.user_b_uid = $1)
        AND f.status = 'pending'
        AND f.requester_uid != $1
    `
    rows, err := db.Query(query, currentUserUID)
    if err != nil {
        log.Printf("Database query failed for received requests: %v", err)
        http.Error(w, "Database query failed", http.StatusInternalServerError)
        return
    }
    defer rows.Close()

    receivedRequests := []FriendInfo{}
    for rows.Next() {
        var requestor FriendInfo
        var avatarURL sql.NullString
        var displayName sql.NullString

        if err := rows.Scan(&requestor.Username, &avatarURL, &displayName); err != nil {
            log.Printf("Error scanning received request row: %v", err)
            continue
        }

        if avatarURL.Valid {
            requestor.AvatarURL = avatarURL.String
        }
        if displayName.Valid {
            requestor.DisplayName = displayName.String
        }

        receivedRequests = append(receivedRequests, requestor)
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(receivedRequests)
}

func acceptFriendRequestHandler(hub *Hub, w http.ResponseWriter, r *http.Request) {
	token, _, err := getVerifiedToken(r)
	if err != nil { http.Error(w, err.Error(), http.StatusUnauthorized); return }
	currentUserUID := token.UID
	var p FriendRequestPayload
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil { http.Error(w, "Invalid request body", http.StatusBadRequest); return }
	senderUsername := p.TargetUsername
	var senderUID string
	err = db.QueryRow("SELECT firebase_uid FROM profiles WHERE username = $1", senderUsername).Scan(&senderUID)
	if err != nil { http.Error(w, "User not found", http.StatusNotFound); return }
	tx, err := db.Begin()
	if err != nil { http.Error(w, "Failed to start transaction", http.StatusInternalServerError); return }
	defer tx.Rollback()
	userA := currentUserUID
	userB := senderUID
	if userA > userB { userA, userB = userB, userA }
	sqlStatement := `UPDATE friendships SET status = 'accepted' WHERE user_a_uid = $1 AND user_b_uid = $2 AND status = 'pending'`
	result, err := tx.Exec(sqlStatement, userA, userB)
	if err != nil {
		http.Error(w, "Failed to accept friend request", http.StatusInternalServerError)
		return
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		http.Error(w, "Friend request not found or already accepted", http.StatusNotFound)
		return
	}

	// Check if conversation already exists between these users
	var existingConversationID int
	checkConvSQL := `
		SELECT c.id
		FROM conversations c
		JOIN conversation_members cm1 ON c.id = cm1.conversation_id
		JOIN conversation_members cm2 ON c.id = cm2.conversation_id
		WHERE c.is_group = false
		AND cm1.profile_uid = $1
		AND cm2.profile_uid = $2
		AND cm1.profile_uid != cm2.profile_uid
		LIMIT 1
	`
	err = tx.QueryRow(checkConvSQL, currentUserUID, senderUID).Scan(&existingConversationID)

	var conversationID int
	if err == sql.ErrNoRows {
		// No existing conversation, create new one
		err = tx.QueryRow("INSERT INTO conversations (is_group) VALUES (false) RETURNING id").Scan(&conversationID)
		if err != nil { http.Error(w, "Failed to create conversation on accept", http.StatusInternalServerError); return }
		_, err = tx.Exec("INSERT INTO conversation_members (conversation_id, profile_uid) VALUES ($1, $2), ($1, $3)", conversationID, currentUserUID, senderUID)
		if err != nil { http.Error(w, "Failed to add members on accept", http.StatusInternalServerError); return }
	} else if err != nil {
		http.Error(w, "Failed to check existing conversation", http.StatusInternalServerError)
		return
	} else {
		// Conversation already exists, use it
		conversationID = existingConversationID
		log.Printf("Conversation %d already exists between %s and %s, reusing it", conversationID, currentUserUID, senderUID)
	}
	if err := tx.Commit(); err != nil { http.Error(w, "Failed to commit transaction", http.StatusInternalServerError); return }

	updatePayload := map[string]string{"type": "conversation_update"}
	updateBytes, _ := json.Marshal(updatePayload)
	recipients := []string{currentUserUID, senderUID}  // Use UIDs instead of usernames
	hub.broadcast <- HubMessage{message: updateBytes, recipients: recipients}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Friend request from %s accepted", senderUsername)
	log.Printf("Friend request from %s accepted by %s, and conversation %d created. Notified UIDs: %v", senderUID, currentUserUID, conversationID, recipients)
}

func declineFriendRequestHandler(w http.ResponseWriter, r *http.Request) {
	token, _, err := getVerifiedToken(r)
	if err != nil { http.Error(w, err.Error(), http.StatusUnauthorized); return }
	currentUserUID := token.UID
	var p FriendRequestPayload
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil { http.Error(w, "Invalid request body", http.StatusBadRequest); return }
	senderUsername := p.TargetUsername
	var senderUID string
	err = db.QueryRow("SELECT firebase_uid FROM profiles WHERE username = $1", senderUsername).Scan(&senderUID)
	if err != nil { http.Error(w, "User not found", http.StatusNotFound); return }
	userA := currentUserUID
	userB := senderUID
	if userA > userB { userA, userB = userB, userA }
	sqlStatement := `DELETE FROM friendships WHERE user_a_uid = $1 AND user_b_uid = $2 AND status = 'pending'`
	result, err := db.Exec(sqlStatement, userA, userB)
	if err != nil {
		http.Error(w, "Failed to decline friend request", http.StatusInternalServerError)
		return
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		http.Error(w, "Friend request not found or already processed", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Friend request from %s declined", senderUsername)
	log.Printf("Friend request from %s declined by %s", senderUID, currentUserUID)
}

// handleCallRejection handles call rejection from notification (when user declines without opening app)
func handleCallRejection(hub *Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get authenticated user
		token, _, err := getVerifiedToken(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		currentUserUID := token.UID

		// Parse request body
		var payload struct {
			RecipientUID string `json:"recipient_uid"`
		}

		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		if payload.RecipientUID == "" {
			http.Error(w, "recipient_uid is required", http.StatusBadRequest)
			return
		}

		log.Printf("📞 Call rejection from %s (declining call from %s)", currentUserUID, payload.RecipientUID)

		// Send call_rejected signal via WebSocket to the caller
		rejectionMessage := map[string]interface{}{
			"type":          "call_rejected",
			"recipient_uid": payload.RecipientUID,
			"sender_uid":    currentUserUID,
		}

		broadcastToUser(hub, payload.RecipientUID, rejectionMessage)

		log.Printf("✅ Call rejection signal sent to %s", payload.RecipientUID)

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"status": "success",
			"message": "Call rejected",
		})
	}
}

func removeFriendHandler(hub *Hub, w http.ResponseWriter, r *http.Request) {
	token, _, err := getVerifiedToken(r)
	if err != nil { http.Error(w, err.Error(), http.StatusUnauthorized); return }
	currentUserUID := token.UID
	var p FriendRequestPayload
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil { http.Error(w, "Invalid request body", http.StatusBadRequest); return }
	targetUsername := p.TargetUsername
	var targetUID string
	err = db.QueryRow("SELECT firebase_uid FROM profiles WHERE username = $1", targetUsername).Scan(&targetUID)
	if err != nil { http.Error(w, "User not found", http.StatusNotFound); return }

	userA := currentUserUID
	userB := targetUID
	if userA > userB { userA, userB = userB, userA }

	sqlStatement := `DELETE FROM friendships WHERE user_a_uid = $1 AND user_b_uid = $2 AND status = 'accepted'`
	result, err := db.Exec(sqlStatement, userA, userB)
	if err != nil {
		http.Error(w, "Failed to remove friend", http.StatusInternalServerError)
		return
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		http.Error(w, "Friendship not found", http.StatusNotFound)
		return
	}

	// Notify both users about the friendship removal
	updatePayload := map[string]string{"type": "friendship_removed"}
	updateBytes, _ := json.Marshal(updatePayload)
	recipients := []string{currentUserUID, targetUID}
	hub.broadcast <- HubMessage{message: updateBytes, recipients: recipients}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Friend %s removed", targetUsername)
	log.Printf("Friend %s removed by %s", targetUID, currentUserUID)
}

// ========== GROUP E2EE - SENDER KEY DISTRIBUTION ==========

// distributeSenderKeyHandler - Upload your sender key distribution message for a group
func distributeSenderKeyHandler(w http.ResponseWriter, r *http.Request) {
	token, _, err := getVerifiedToken(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	currentUserUID := token.UID

	vars := mux.Vars(r)
	groupIDStr := vars["groupId"]
	groupID, err := strconv.Atoi(groupIDStr)
	if err != nil {
		http.Error(w, "Invalid group ID", http.StatusBadRequest)
		return
	}

	var payload struct {
		SenderKeyDistribution string `json:"sender_key_distribution"`
		DeviceID              int    `json:"device_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Verify user is member and get current key generation
	var isMember bool
	var currentGeneration int
	err = db.QueryRow(`
		SELECT EXISTS(
			SELECT 1 FROM conversation_members
			WHERE conversation_id = $1 AND profile_uid = $2
		),
		COALESCE((SELECT current_key_generation FROM conversations WHERE id = $1), 1)
	`, groupID, currentUserUID).Scan(&isMember, &currentGeneration)

	if err != nil || !isMember {
		http.Error(w, "Not a member of this group", http.StatusForbidden)
		return
	}

	// Store sender key with current generation
	_, err = db.Exec(`
		INSERT INTO group_sender_keys (conversation_id, sender_uid, device_id, sender_key_distribution, key_generation, created_at, rotated_at)
		VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
		ON CONFLICT (conversation_id, sender_uid, device_id)
		DO UPDATE SET sender_key_distribution = $4, key_generation = $5, rotated_at = NOW()
	`, groupID, currentUserUID, payload.DeviceID, payload.SenderKeyDistribution, currentGeneration)

	if err != nil {
		log.Printf("Error storing sender key: %v", err)
		http.Error(w, "Failed to store sender key", http.StatusInternalServerError)
		return
	}

	log.Printf("Sender key distributed for user %s in group %d (generation %d)", currentUserUID, groupID, currentGeneration)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"key_generation": currentGeneration,
	})
}

// getGroupSenderKeysHandler - Get all sender keys for a group
func getGroupSenderKeysHandler(w http.ResponseWriter, r *http.Request) {
	token, _, err := getVerifiedToken(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	currentUserUID := token.UID

	vars := mux.Vars(r)
	groupIDStr := vars["groupId"]
	groupID, err := strconv.Atoi(groupIDStr)
	if err != nil {
		http.Error(w, "Invalid group ID", http.StatusBadRequest)
		return
	}

	// Verify user is member and get current generation
	var isMember bool
	var currentGeneration int
	err = db.QueryRow(`
		SELECT EXISTS(
			SELECT 1 FROM conversation_members
			WHERE conversation_id = $1 AND profile_uid = $2
		),
		COALESCE((SELECT current_key_generation FROM conversations WHERE id = $1), 1)
	`, groupID, currentUserUID).Scan(&isMember, &currentGeneration)

	if err != nil || !isMember {
		http.Error(w, "Not a member of this group", http.StatusForbidden)
		return
	}

	// Get all sender keys for current generation (except own key)
	rows, err := db.Query(`
		SELECT sender_uid, device_id, sender_key_distribution
		FROM group_sender_keys
		WHERE conversation_id = $1
		  AND sender_uid != $2
		  AND key_generation = $3
	`, groupID, currentUserUID, currentGeneration)

	if err != nil {
		log.Printf("Error fetching sender keys: %v", err)
		http.Error(w, "Failed to fetch sender keys", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type SenderKey struct {
		SenderUID             string `json:"sender_uid"`
		DeviceID              int    `json:"device_id"`
		SenderKeyDistribution string `json:"sender_key_distribution"`
	}

	senderKeys := make([]SenderKey, 0)
	for rows.Next() {
		var sk SenderKey
		if err := rows.Scan(&sk.SenderUID, &sk.DeviceID, &sk.SenderKeyDistribution); err != nil {
			log.Printf("Error scanning sender key: %v", err)
			continue
		}
		senderKeys = append(senderKeys, sk)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(senderKeys)
}

// triggerKeyRotation - Increments key generation and logs rotation
func triggerKeyRotation(db *sql.DB, groupID int, reason string, triggeredByUID string, affectedMemberUID *string) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %v", err)
	}
	defer tx.Rollback()

	// Get current generation
	var currentGen int
	err = tx.QueryRow(`
		SELECT COALESCE(current_key_generation, 1)
		FROM conversations
		WHERE id = $1
	`, groupID).Scan(&currentGen)

	if err != nil {
		return fmt.Errorf("failed to get current generation: %v", err)
	}

	newGen := currentGen + 1

	// Update conversation with new generation
	_, err = tx.Exec(`
		UPDATE conversations
		SET current_key_generation = $1,
		    last_rotation_at = NOW(),
		    message_count_since_rotation = 0
		WHERE id = $2
	`, newGen, groupID)

	if err != nil {
		return fmt.Errorf("failed to update generation: %v", err)
	}

	// Delete old sender keys (they're now invalid)
	_, err = tx.Exec(`
		DELETE FROM group_sender_keys
		WHERE conversation_id = $1 AND key_generation < $2
	`, groupID, newGen)

	if err != nil {
		return fmt.Errorf("failed to delete old keys: %v", err)
	}

	// Log rotation in history
	_, err = tx.Exec(`
		INSERT INTO group_key_rotations
		(conversation_id, rotation_reason, triggered_by_uid, old_generation, new_generation, affected_member_uid)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, groupID, reason, triggeredByUID, currentGen, newGen, affectedMemberUID)

	if err != nil {
		return fmt.Errorf("failed to log rotation: %v", err)
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit rotation: %v", err)
	}

	log.Printf("🔄 Key rotation triggered for group %d: %s (Gen %d → %d)", groupID, reason, currentGen, newGen)
	return nil
}

// checkAndRotatePeriodicHandler - Check if periodic rotation needed
func checkAndRotatePeriodicHandler(hub *Hub, w http.ResponseWriter, r *http.Request) {
	token, _, err := getVerifiedToken(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	currentUserUID := token.UID

	vars := mux.Vars(r)
	groupIDStr := vars["groupId"]
	groupID, err := strconv.Atoi(groupIDStr)
	if err != nil {
		http.Error(w, "Invalid group ID", http.StatusBadRequest)
		return
	}

	// Verify membership
	var isMember bool
	err = db.QueryRow(`
		SELECT EXISTS(
			SELECT 1 FROM conversation_members
			WHERE conversation_id = $1 AND profile_uid = $2
		)
	`, groupID, currentUserUID).Scan(&isMember)

	if err != nil || !isMember {
		http.Error(w, "Not a member", http.StatusForbidden)
		return
	}

	// Check rotation criteria: 30 days OR 10000 messages
	var lastRotation time.Time
	var messageCount int
	err = db.QueryRow(`
		SELECT COALESCE(last_rotation_at, created_at),
		       COALESCE(message_count_since_rotation, 0)
		FROM conversations
		WHERE id = $1
	`, groupID).Scan(&lastRotation, &messageCount)

	if err != nil {
		http.Error(w, "Failed to check rotation status", http.StatusInternalServerError)
		return
	}

	daysSinceRotation := time.Since(lastRotation).Hours() / 24
	needsRotation := daysSinceRotation >= 30 || messageCount >= 10000

	if needsRotation {
		if err := triggerKeyRotation(db, groupID, "periodic", currentUserUID, nil); err != nil {
			log.Printf("Periodic rotation failed: %v", err)
			http.Error(w, "Failed to rotate keys", http.StatusInternalServerError)
			return
		}

		// Notify all members
		allMemberUIDs, err := getConversationMemberUIDs(db, groupID)
		if err == nil {
			notificationPayload := map[string]interface{}{
				"type": "conversation_update",
				"conversation_id": groupID,
				"key_rotation_required": true,
				"reason": "periodic",
			}
			notificationBytes, _ := json.Marshal(notificationPayload)
			hub.broadcast <- HubMessage{message: notificationBytes, recipients: allMemberUIDs}
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"rotated": true,
			"reason": fmt.Sprintf("%.0f days or %d messages", daysSinceRotation, messageCount),
		})
	} else {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"rotated": false,
			"days_since_rotation": int(daysSinceRotation),
			"messages_since_rotation": messageCount,
		})
	}
}

func getConversationsHandler(w http.ResponseWriter, r *http.Request) {
	token, _, err := getVerifiedToken(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	currentUserUID := token.UID

	// The SQL query now also selects the partner's UID and display_name.
	query := `
		SELECT DISTINCT ON (c.id)
			c.id,
			c.is_group,
			c.group_name,
			c.creator_uid,
			c.group_avatar_url,
			p.username AS partner_username,
			p.display_name AS partner_display_name,
			CASE 
				WHEN p.avatar_privacy = 'nobody' THEN NULL
				WHEN p.avatar_privacy = 'contacts' AND NOT EXISTS (
					SELECT 1 FROM friendships f 
					WHERE ((f.user_a_uid = p.firebase_uid AND f.user_b_uid = $1) OR (f.user_a_uid = $1 AND f.user_b_uid = p.firebase_uid))
					  AND f.status = 'accepted'
				) THEN NULL
				ELSE p.profile_avatar_url 
			END AS partner_avatar_url,
			p.firebase_uid AS partner_uid
		FROM
			conversations AS c
		JOIN
			conversation_members AS me ON c.id = me.conversation_id
		LEFT JOIN
			conversation_members AS them ON me.conversation_id = them.conversation_id AND me.profile_uid != them.profile_uid
		LEFT JOIN
			profiles AS p ON them.profile_uid = p.firebase_uid
		WHERE
			me.profile_uid = $1
		ORDER BY c.id DESC;
	`
	rows, err := db.Query(query, currentUserUID)
	if err != nil {
		log.Printf("DB error fetching conversation list for %s: %v", currentUserUID, err)
		http.Error(w, "DB error fetching conversation list", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	conversations := []ConversationInfoResponse{}
	for rows.Next() {
		var convo ConversationInfoResponse
		var groupName, creatorUID, groupAvatarURL, partnerUsername, partnerDisplayName, partnerAvatarURL, partnerUID sql.NullString

		// Scan including partner_display_name
		if err := rows.Scan(&convo.ConversationID, &convo.IsGroup, &groupName, &creatorUID, &groupAvatarURL, &partnerUsername, &partnerDisplayName, &partnerAvatarURL, &partnerUID); err != nil {
			log.Printf("Error scanning conversation row: %v", err)
			continue
		}

		if creatorUID.Valid {
			convo.CreatorUID = creatorUID.String
		}

		if convo.IsGroup {
			if groupName.Valid {
				convo.ChatTitle = groupName.String
			} else {
				convo.ChatTitle = "Unnamed Group"
			}
			if groupAvatarURL.Valid {
				convo.AvatarURL = groupAvatarURL.String
			}
		} else {
			// If it's a 1-on-1 chat, add the partner's UID to the response.
			if partnerUID.Valid {
				convo.PartnerUID = partnerUID.String
			}
			// Use display_name if available, fallback to username
			if partnerDisplayName.Valid && partnerDisplayName.String != "" {
				convo.ChatTitle = partnerDisplayName.String
			} else if partnerUsername.Valid {
				convo.ChatTitle = partnerUsername.String
			} else {
				convo.ChatTitle = "Private Chat"
			}
			if partnerAvatarURL.Valid {
				convo.AvatarURL = partnerAvatarURL.String
			}
		}
		conversations = append(conversations, convo)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(conversations)
}

func getFriendsListHandler(w http.ResponseWriter, r *http.Request) {
	token, _, err := getVerifiedToken(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	currentUserUID := token.UID

	query := `
		SELECT p.username, 
		       CASE WHEN p.avatar_privacy = 'nobody' THEN NULL ELSE p.profile_avatar_url END AS filtered_avatar_url, 
		       p.display_name 
		FROM profiles p
		JOIN friendships f ON (p.firebase_uid = f.user_a_uid OR p.firebase_uid = f.user_b_uid)
		WHERE (f.user_a_uid = $1 OR f.user_b_uid = $1)
		AND f.status = 'accepted'
		AND p.firebase_uid != $1
	`
	rows, err := db.Query(query, currentUserUID)
	if err != nil {
		http.Error(w, "Database query failed", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	friends := []FriendInfo{}
	for rows.Next() {
		var friend FriendInfo
		var avatarURL sql.NullString
		var displayName sql.NullString
		if err := rows.Scan(&friend.Username, &avatarURL, &displayName); err != nil {
			log.Printf("Error scanning friend data: %v", err)
			continue
		}
		if avatarURL.Valid {
			friend.AvatarURL = avatarURL.String
		}
		if displayName.Valid {
			friend.DisplayName = displayName.String
		}
		friends = append(friends, friend)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(friends)
}

func startOrGetConversationHandler(w http.ResponseWriter, r *http.Request) {
	token, _, err := getVerifiedToken(r)
	if err != nil { http.Error(w, err.Error(), http.StatusUnauthorized); return }
	currentUserUID := token.UID
	var p StartConversationPayload
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil { http.Error(w, "Invalid request body", http.StatusBadRequest); return }
	targetUsername := p.TargetUsername
	var targetUserUID string
	err = db.QueryRow("SELECT firebase_uid FROM profiles WHERE username = $1", targetUsername).Scan(&targetUserUID)
	if err != nil { http.Error(w, "Target user not found", http.StatusNotFound); return }
	var conversationID int
	query := `
		SELECT cm1.conversation_id FROM conversation_members cm1
		JOIN conversation_members cm2 ON cm1.conversation_id = cm2.conversation_id
		JOIN conversations c ON cm1.conversation_id = c.id
		WHERE cm1.profile_uid = $1 AND cm2.profile_uid = $2 AND c.is_group = false
	`
	err = db.QueryRow(query, currentUserUID, targetUserUID).Scan(&conversationID)
	if err == nil {
		log.Printf("Found existing conversation (%d) between %s and %s", conversationID, currentUserUID, targetUserUID)
		json.NewEncoder(w).Encode(map[string]int{"conversationId": conversationID})
		return
	}
	tx, err := db.Begin()
	if err != nil { http.Error(w, "Failed to start transaction", http.StatusInternalServerError); return }
	defer tx.Rollback()
	err = tx.QueryRow("INSERT INTO conversations (is_group) VALUES (false) RETURNING id").Scan(&conversationID)
	if err != nil { http.Error(w, "Failed to create conversation", http.StatusInternalServerError); return }
	_, err = tx.Exec("INSERT INTO conversation_members (conversation_id, profile_uid) VALUES ($1, $2), ($1, $3)", conversationID, currentUserUID, targetUserUID)
	if err != nil { http.Error(w, "Failed to add members to conversation", http.StatusInternalServerError); return }
	if err := tx.Commit(); err != nil { http.Error(w, "Failed to commit transaction", http.StatusInternalServerError); return }
	log.Printf("Created new conversation (%d) between %s and %s", conversationID, currentUserUID, targetUserUID)
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]int{"conversationId": conversationID})
}

func getSentFriendRequestsHandler(w http.ResponseWriter, r *http.Request) {
    token, _, err := getVerifiedToken(r)
    if err != nil {
        http.Error(w, err.Error(), http.StatusUnauthorized)
        return
    }
    currentUserUID := token.UID

    // Change 1: The SQL query now also selects display_name and profile_avatar_url
    query := `
        SELECT p.username, p.display_name, p.profile_avatar_url FROM profiles p
        JOIN friendships f ON (
            (p.firebase_uid = f.user_a_uid AND f.user_b_uid = $1) OR
            (p.firebase_uid = f.user_b_uid AND f.user_a_uid = $1)
        )
        WHERE f.requester_uid = $1 AND f.status = 'pending'
        AND p.firebase_uid != $1
    `
    rows, err := db.Query(query, currentUserUID)
    if err != nil {
        log.Printf("Database query failed for sent requests: %v", err)
        http.Error(w, "Database query failed", http.StatusInternalServerError)
        return
    }
    defer rows.Close()

    // Change 2: We create a slice of our new struct, not a slice of strings.
    sentRequests := []FriendInfo{}
    for rows.Next() {
        // Change 3: Create an instance of our struct to hold the data for one user.
        var requestInfo FriendInfo
        // Change 4: Use sql.NullString to safely handle NULL values from the database.
        var displayName sql.NullString
        var avatarURL sql.NullString

        // Change 5: Scan into the three variables.
        if err := rows.Scan(&requestInfo.Username, &displayName, &avatarURL); err != nil {
            log.Printf("Error scanning sent request row: %v", err)
            continue
        }

        // Change 6: Assign display name if valid
        if displayName.Valid {
            requestInfo.DisplayName = displayName.String
        }

        // Change 7: If the avatar URL from the database is valid (not NULL), assign it.
        if avatarURL.Valid {
            requestInfo.AvatarURL = avatarURL.String
        }

        // Change 8: Append the whole struct to our results slice.
        sentRequests = append(sentRequests, requestInfo)
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(sentRequests)
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set headers to allow requests from any origin
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")

		// If this is a preflight request, respond immediately
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Otherwise, pass the request to the next handler in the chain
		next.ServeHTTP(w, r)
	})
}

func getMyProfileHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		token, _, err := getVerifiedToken(r)
		if err != nil {
			handleAuthError(w, err)
			return
		}
		uid := token.UID

		// Check if profile exists and get all profile data including nullable phone_hash and avatar_privacy
		var username string
		var profileAvatarURL sql.NullString
		var displayName sql.NullString
		var phoneHash sql.NullString
		var avatarPrivacy sql.NullString
		err = db.QueryRowContext(r.Context(), "SELECT username, profile_avatar_url, display_name, phone_hash, avatar_privacy FROM profiles WHERE firebase_uid = $1", uid).Scan(&username, &profileAvatarURL, &displayName, &phoneHash, &avatarPrivacy)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				// Distinguish 404 profile_not_found from 500 server_error so client knows profile hasn't been created
				sendJSONError(w, http.StatusNotFound, "profile_not_found", "User is authenticated but profile is not created yet")
				return
			}
			log.Printf("getMyProfileHandler: DB error for %s: %v", uid, err)
			sendJSONError(w, http.StatusInternalServerError, "server_error", "Failed to query profile")
			return
		}

		privacy := "everyone"
		if avatarPrivacy.Valid && avatarPrivacy.String != "" {
			privacy = avatarPrivacy.String
		}

		// Build response compatible with client expectations
		response := map[string]interface{}{
			"status":              "found",
			"uid":                 uid,
			"username":            username,
			"display_name":        displayName.String,
			"profile_picture_url": profileAvatarURL.String,
			"avatarUrl":           profileAvatarURL.String,
			"avatar_privacy":      privacy,
			"avatarPrivacy":      privacy,
			"has_phone":           phoneHash.Valid && phoneHash.String != "",
		}
		if phoneHash.Valid && phoneHash.String != "" {
			response["phone_hash"] = phoneHash.String
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}
}

// deleteAccountHandler permanently deletes a user account and all associated data
func deleteAccountHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Verify user authentication
		token, _, err := getVerifiedToken(r)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		uid := token.UID

		log.Printf("🗑️ Account deletion requested for user: %s", uid)

		// Start transaction
		tx, err := db.Begin()
		if err != nil {
			log.Printf("❌ Failed to start transaction for account deletion: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		defer tx.Rollback()

		// Delete in correct order (respecting foreign keys)

		// 1. Delete Signal Protocol keys
		_, err = tx.Exec("DELETE FROM one_time_pre_keys WHERE firebase_uid = $1", uid)
		if err != nil {
			log.Printf("❌ Failed to delete one_time_pre_keys: %v", err)
			http.Error(w, "Failed to delete account", http.StatusInternalServerError)
			return
		}

		_, err = tx.Exec("DELETE FROM signed_pre_keys WHERE firebase_uid = $1", uid)
		if err != nil {
			log.Printf("❌ Failed to delete signed_pre_keys: %v", err)
			http.Error(w, "Failed to delete account", http.StatusInternalServerError)
			return
		}

		_, err = tx.Exec("DELETE FROM identity_keys WHERE firebase_uid = $1", uid)
		if err != nil {
			log.Printf("❌ Failed to delete identity_keys: %v", err)
			http.Error(w, "Failed to delete account", http.StatusInternalServerError)
			return
		}

		// 2. Delete group sender keys
		_, err = tx.Exec("DELETE FROM group_sender_keys WHERE sender_uid = $1", uid)
		if err != nil {
			log.Printf("❌ Failed to delete group_sender_keys: %v", err)
			http.Error(w, "Failed to delete account", http.StatusInternalServerError)
			return
		}

		// 3. Delete message-related data
		_, err = tx.Exec("DELETE FROM message_status WHERE recipient_uid = $1", uid)
		if err != nil {
			log.Printf("❌ Failed to delete message_status: %v", err)
			http.Error(w, "Failed to delete account", http.StatusInternalServerError)
			return
		}

		_, err = tx.Exec("DELETE FROM message_deletions WHERE deleted_by_uid = $1", uid)
		if err != nil {
			log.Printf("❌ Failed to delete message_deletions: %v", err)
			http.Error(w, "Failed to delete account", http.StatusInternalServerError)
			return
		}

		// 4. Delete offline queue and pending updates
		_, err = tx.Exec("DELETE FROM offline_message_queue WHERE recipient_uid = $1 OR sender_uid = $1", uid)
		if err != nil {
			log.Printf("❌ Failed to delete offline_message_queue: %v", err)
			http.Error(w, "Failed to delete account", http.StatusInternalServerError)
			return
		}

		_, err = tx.Exec("DELETE FROM pending_status_updates WHERE user_uid = $1", uid)
		if err != nil {
			log.Printf("❌ Failed to delete pending_status_updates: %v", err)
			http.Error(w, "Failed to delete account", http.StatusInternalServerError)
			return
		}

		// 5. Delete call logs
		_, err = tx.Exec("DELETE FROM call_logs WHERE caller_uid = $1 OR receiver_uid = $1", uid)
		if err != nil {
			log.Printf("❌ Failed to delete call_logs: %v", err)
			http.Error(w, "Failed to delete account", http.StatusInternalServerError)
			return
		}

		// 6. Delete messages sent by the user
		_, err = tx.Exec("DELETE FROM messages WHERE sender_uid = $1", uid)
		if err != nil {
			log.Printf("❌ Failed to delete messages: %v", err)
			http.Error(w, "Failed to delete account", http.StatusInternalServerError)
			return
		}

		// 7. Delete conversation members
		_, err = tx.Exec("DELETE FROM conversation_members WHERE profile_uid = $1", uid)
		if err != nil {
			log.Printf("❌ Failed to delete conversation_members: %v", err)
			http.Error(w, "Failed to delete account", http.StatusInternalServerError)
			return
		}

		// 8. Delete friendships
		_, err = tx.Exec("DELETE FROM friendships WHERE user_a_uid = $1 OR user_b_uid = $1", uid)
		if err != nil {
			log.Printf("❌ Failed to delete friendships: %v", err)
			http.Error(w, "Failed to delete account", http.StatusInternalServerError)
			return
		}

		// 9. Delete devices
		_, err = tx.Exec("DELETE FROM devices WHERE firebase_uid = $1", uid)
		if err != nil {
			log.Printf("❌ Failed to delete devices: %v", err)
			http.Error(w, "Failed to delete account", http.StatusInternalServerError)
			return
		}

		// 10. Finally, delete the profile (this will cascade to remaining references)
		_, err = tx.Exec("DELETE FROM profiles WHERE firebase_uid = $1", uid)
		if err != nil {
			log.Printf("❌ Failed to delete profile: %v", err)
			http.Error(w, "Failed to delete account", http.StatusInternalServerError)
			return
		}

		// Commit transaction
		if err = tx.Commit(); err != nil {
			log.Printf("❌ Failed to commit account deletion: %v", err)
			http.Error(w, "Failed to delete account", http.StatusInternalServerError)
			return
		}

		log.Printf("✅ Account successfully deleted for user: %s", uid)

		// Send success response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message": "Account deleted successfully",
			"uid":     uid,
		})
	}
}


func createGroupHandler(hub *Hub, w http.ResponseWriter, r *http.Request) {
	token, _, err := getVerifiedToken(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	creatorUID := token.UID

	var p CreateGroupPayload
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	trimmedGroupName := strings.TrimSpace(p.GroupName)
	if trimmedGroupName == "" {
		http.Error(w, "Group name cannot be empty", http.StatusBadRequest)
		return
	}

	// Check group member limit (creator + invited members)
	totalMembers := 1 + len(p.MemberUsernames)
	if totalMembers > MAX_GROUP_MEMBERS {
		http.Error(w, fmt.Sprintf("Group cannot have more than %d members (including you)", MAX_GROUP_MEMBERS), http.StatusBadRequest)
		return
	}

	tx, err := db.Begin()
	if err != nil {
		log.Printf("ERROR_GO: createGroupHandler - Failed to start transaction: %v", err)
		http.Error(w, "Failed to start transaction", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	var existingID int
	err = tx.QueryRow("SELECT id FROM conversations WHERE group_name = $1", trimmedGroupName).Scan(&existingID)

	if err == nil {
		http.Error(w, "A group with this name already exists.", http.StatusConflict)
		return
	}

	if err != sql.ErrNoRows {
		log.Printf("DATABASE_ERROR: Checking for existing group name failed: %v", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	var conversationID int
	description := strings.TrimSpace(p.Description)
	err = tx.QueryRow("INSERT INTO conversations (is_group, group_name, description, creator_uid, updated_at) VALUES (true, $1, $2, $3, NOW()) RETURNING id", trimmedGroupName, description, creatorUID).Scan(&conversationID)
	if err != nil {
		log.Printf("ERROR_GO: createGroupHandler - Failed to create conversation: %v", err)
		http.Error(w, "Failed to create conversation", http.StatusInternalServerError)
		return
	}

	query := "SELECT firebase_uid FROM profiles WHERE username = ANY($1)"
	rows, err := tx.Query(query, pq.Array(p.MemberUsernames))
	if err != nil {
		log.Printf("ERROR_GO: createGroupHandler - Failed to find members: %v", err)
		http.Error(w, "Failed to find members", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	memberUIDs := []string{creatorUID}
	for rows.Next() {
		var uid string
		if err := rows.Scan(&uid); err != nil {
			log.Printf("ERROR_GO: createGroupHandler - Error scanning member UID: %v", err)
			continue
		}
		isCreator := false
		for _, existingUID := range memberUIDs {
			if uid == existingUID {
				isCreator = true
				break
			}
		}
		if !isCreator {
			memberUIDs = append(memberUIDs, uid)
		}
	}

	for _, uid := range memberUIDs {
		role := "member"
		if uid == creatorUID {
			role = "owner"
		}
		_, err = tx.Exec("INSERT INTO conversation_members (conversation_id, profile_uid, role, joined_at) VALUES ($1, $2, $3, NOW())", conversationID, uid, role)
		if err != nil {
			log.Printf("Failed to add member %s to conversation %d: %v", uid, conversationID, err)
			http.Error(w, "Failed to add member to conversation", http.StatusInternalServerError); return
		}
	}

	if err := tx.Commit(); err != nil {
		log.Printf("ERROR_GO: createGroupHandler - Failed to commit transaction: %v", err)
		http.Error(w, "Failed to commit transaction", http.StatusInternalServerError)
		return
	}
	log.Printf("Created new group '%s' (%d) with members UIDs: %v", trimmedGroupName, conversationID, memberUIDs)

	notificationPayload := map[string]string{"type": "conversation_update"}
	notificationBytes, _ := json.Marshal(notificationPayload)
	hub.broadcast <- HubMessage{message: notificationBytes, recipients: memberUIDs}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"conversationId": conversationID,
		"groupName":      trimmedGroupName,
		"creatorUid":     creatorUID,
	})
}

func deleteMessageHandler(hub *Hub, db *sql.DB) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        token, _, err := getVerifiedToken(r)
        if err != nil {
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }

        vars := mux.Vars(r)
        idStr := vars["id"]
        id, err := strconv.ParseInt(idStr, 10, 64)
        if err != nil {
            http.Error(w, "Invalid message ID", http.StatusBadRequest)
            return
        }

        log.Printf("deleteMessageHandler: Deleting message ID %d for user %s", id, token.UID)

        // Parse request body to get deletion type
        var deleteRequest struct {
            DeletionType string `json:"deletion_type"` // "delete_for_me" or "delete_for_everyone"
        }
        
        if err := json.NewDecoder(r.Body).Decode(&deleteRequest); err != nil {
            http.Error(w, "Invalid request body", http.StatusBadRequest)
            return
        }

        var senderUID string
        var conversationID int
        
        err = db.QueryRow("SELECT sender_uid, conversation_id FROM messages WHERE id = $1", id).Scan(&senderUID, &conversationID)
        if err != nil {
            http.Error(w, "Message not found", http.StatusNotFound)
            return
        }

        // For "delete_for_everyone", only sender can delete
        if deleteRequest.DeletionType == "delete_for_everyone" && token.UID != senderUID {
            http.Error(w, "Forbidden: You can only delete your own messages for everyone", http.StatusForbidden)
            return
        }

        // Handle deletion based on type
        if deleteRequest.DeletionType == "delete_for_everyone" {
    // Use content update and mark as deleted (not encrypted)
    _, err = db.Exec("UPDATE messages SET content = $1, message_type = $2 WHERE id = $3",
        []byte("This message was deleted"), "deleted", id)
		} else {
    	// Personal deletion - record in deletions table
    	_, err = db.Exec(`
        	INSERT INTO message_deletions (message_id, deleted_by_uid, deletion_type) 
        	VALUES ($1, $2, $3)
       	 	ON CONFLICT (message_id, deleted_by_uid) DO NOTHING
    		`, id, token.UID, deleteRequest.DeletionType)


			if err != nil {
        		log.Printf("ERROR inserting into message_deletions: %v", err)
    		} else {
        		log.Printf("Successfully inserted deletion record: message_id=%d, user=%s, type=%s", id, token.UID, deleteRequest.DeletionType)
    		}
        }

        if err != nil {
            http.Error(w, "Failed to delete message", http.StatusInternalServerError)
            return
        }

        // Broadcast deletion based on type
        deletePayload := map[string]interface{}{
            "type":           "message_deleted",
            "message_id":     id,
            "conversation_id": conversationID,
            "deletion_type":  deleteRequest.DeletionType,
            "deleted_by":     token.UID,
        }


        if deleteRequest.DeletionType == "delete_for_everyone" {
            // Broadcast to all conversation members
            memberUIDs, err := getConversationMemberUIDs(db, conversationID)
            if err != nil {
                log.Printf("ERROR: Failed to get conversation members: %v", err)
            } else {
                log.Printf("Broadcasting delete_for_everyone to %d members: %v", len(memberUIDs), memberUIDs)
                for _, uid := range memberUIDs {
                    log.Printf("Broadcasting to member: %s", uid)
                    broadcastToUser(hub, uid, deletePayload)
                }
            }
        } else {
            // Only notify the deleting user
            log.Printf("Broadcasting delete_for_me to user: %s", token.UID)
            broadcastToUser(hub, token.UID, deletePayload)
        }

        w.WriteHeader(http.StatusOK)
    }
}

func getConversationMemberUIDs(db *sql.DB, conversationID int) ([]string, error) {
    rows, err := db.Query(`
        SELECT cm.profile_uid
        FROM conversation_members cm
        WHERE cm.conversation_id = $1
    `, conversationID)
    
    if err != nil {
        return nil, fmt.Errorf("failed to fetch conversation members: %v", err)
    }
    defer rows.Close()
    
    var memberUIDs []string
    for rows.Next() {
        var uid string
        if err := rows.Scan(&uid); err != nil {
            continue
        }
        memberUIDs = append(memberUIDs, uid)
    }
    
    return memberUIDs, nil
}

// You will likely need a helper function like this if you don't have one already.
// It retrieves all members of a conversation so the hub can target them.
func getConversationMemberUsernames(db *sql.DB, conversationID int) ([]string, error) {
	rows, err := db.Query("SELECT p.username FROM profiles p JOIN conversation_members cm ON p.firebase_uid = cm.profile_uid WHERE cm.conversation_id = $1", conversationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var usernames []string
	for rows.Next() {
		var username string
		if err := rows.Scan(&username); err != nil {
			continue
		}
		usernames = append(usernames, username)
	}
	return usernames, nil
}

func deleteGroupHandler(hub *Hub, w http.ResponseWriter, r *http.Request) {
	token, _, err := getVerifiedToken(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	currentUserUID := token.UID

	vars := mux.Vars(r)
	idStr := vars["groupId"]
	conversationID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid group ID", http.StatusBadRequest)
		return
	}

	var creatorUID sql.NullString
	var isGroup bool
	err = db.QueryRow("SELECT is_group, creator_uid FROM conversations WHERE id = $1", conversationID).Scan(&isGroup, &creatorUID)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Group not found", http.StatusNotFound)
			return
		}
		log.Printf("DB error checking group creator for ID %d: %v", conversationID, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if !isGroup {
		http.Error(w, "Not a group conversation", http.StatusBadRequest)
		return
	}

	var userRole string
	_ = db.QueryRow("SELECT role FROM conversation_members WHERE conversation_id = $1 AND profile_uid = $2", conversationID, currentUserUID).Scan(&userRole)

	isOwner := userRole == "owner" || (creatorUID.Valid && creatorUID.String == currentUserUID)
	if !isOwner {
		http.Error(w, "Forbidden: Only the group owner can delete the group", http.StatusForbidden)
		return
	}

	tx, err := db.Begin()
	if err != nil {
		log.Printf("Failed to start transaction for group deletion: %v", err)
		http.Error(w, "Failed to delete group (transaction error)", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	memberRows, err := tx.Query("SELECT profile_uid FROM conversation_members WHERE conversation_id = $1", conversationID)
	if err != nil {
		log.Printf("DB error getting group members for deletion: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer memberRows.Close()

	var memberUIDs []string
	for memberRows.Next() {
		var uid string
		if err := memberRows.Scan(&uid); err != nil {
			log.Printf("Error scanning member UID for group deletion: %v", err)
			continue
		}
		memberUIDs = append(memberUIDs, uid)
	}

	// Delete in order: tables without CASCADE first
	_, err = tx.Exec("DELETE FROM pending_status_updates WHERE conversation_id = $1", conversationID)
	if err != nil {
		log.Printf("DB error deleting pending status updates for group %d: %v", conversationID, err)
		http.Error(w, "Failed to delete group status updates", http.StatusInternalServerError)
		return
	}

	_, err = tx.Exec("DELETE FROM offline_message_queue WHERE conversation_id = $1", conversationID)
	if err != nil {
		log.Printf("DB error deleting offline queue for group %d: %v", conversationID, err)
		http.Error(w, "Failed to delete group offline queue", http.StatusInternalServerError)
		return
	}

	_, err = tx.Exec("DELETE FROM call_logs WHERE conversation_id = $1", conversationID)
	if err != nil {
		log.Printf("DB error deleting call logs for group %d: %v", conversationID, err)
		http.Error(w, "Failed to delete group call logs", http.StatusInternalServerError)
		return
	}

	_, err = tx.Exec("DELETE FROM messages WHERE conversation_id = $1", conversationID)
	if err != nil {
		log.Printf("DB error deleting messages for group %d: %v", conversationID, err)
		http.Error(w, "Failed to delete group messages", http.StatusInternalServerError)
		return
	}

	_, err = tx.Exec("DELETE FROM group_sender_keys WHERE conversation_id = $1", conversationID)
	if err != nil {
		log.Printf("DB error deleting sender keys for group %d: %v", conversationID, err)
		http.Error(w, "Failed to delete group sender keys", http.StatusInternalServerError)
		return
	}

	_, err = tx.Exec("DELETE FROM group_invite_links WHERE conversation_id = $1", conversationID)
	if err != nil {
		log.Printf("DB error deleting invite links for group %d: %v", conversationID, err)
		http.Error(w, "Failed to delete group invite links", http.StatusInternalServerError)
		return
	}

	_, _ = tx.Exec("DELETE FROM group_join_requests WHERE conversation_id = $1", conversationID)

	_, err = tx.Exec("DELETE FROM conversation_members WHERE conversation_id = $1", conversationID)
	if err != nil {
		log.Printf("DB error deleting members for group %d: %v", conversationID, err)
		http.Error(w, "Failed to delete group members", http.StatusInternalServerError)
		return
	}

	_, err = tx.Exec("DELETE FROM conversations WHERE id = $1", conversationID)
	if err != nil {
		log.Printf("DB error deleting conversation %d: %v", conversationID, err)
		http.Error(w, "Failed to delete group", http.StatusInternalServerError)
		return
	}

	if err := tx.Commit(); err != nil {
		log.Printf("Failed to commit group deletion transaction: %v", err)
		http.Error(w, "Failed to delete group (commit error)", http.StatusInternalServerError)
		return
	}

	log.Printf("Group ID %d deleted by creator %s", conversationID, currentUserUID)

	notificationPayload := map[string]interface{}{
		"type":           "group_deleted",
		"conversationId": conversationID,
	}
	notificationBytes, err := json.Marshal(notificationPayload)
	if err != nil {
		log.Printf("Error marshalling group_deleted payload: %v", err)
	} else {
		hub.broadcast <- HubMessage{message: notificationBytes, recipients: memberUIDs}
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Group %d deleted successfully", conversationID)
}

func getGroupInfoHandler(w http.ResponseWriter, r *http.Request) {
	token, _, err := getVerifiedToken(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	currentUserUID := token.UID

	vars := mux.Vars(r)
	groupIDStr := vars["groupId"]
	groupID, err := strconv.Atoi(groupIDStr)
	if err != nil {
		http.Error(w, "Invalid group ID", http.StatusBadRequest)
		return
	}

	// Verify user is a member of this group
	var isMember bool
	err = db.QueryRow(`
		SELECT EXISTS(
			SELECT 1 FROM conversation_members
			WHERE conversation_id = $1 AND profile_uid = $2
		)
	`, groupID, currentUserUID).Scan(&isMember)

	if err != nil || !isMember {
		http.Error(w, "Not a member of this group", http.StatusForbidden)
		return
	}

	// Get group details
	var response GroupInfoResponse
	var description, avatarURL sql.NullString
	var editPerm, sendPerm, addPerm sql.NullString
	var reqApproval sql.NullBool
	err = db.QueryRow(`
		SELECT id, group_name, description, creator_uid, group_avatar_url, created_at, updated_at,
		       edit_group_info_permission, send_messages_permission, add_members_permission, require_admin_approval
		FROM conversations
		WHERE id = $1 AND is_group = true
	`, groupID).Scan(
		&response.ConversationID,
		&response.GroupName,
		&description,
		&response.CreatorUID,
		&avatarURL,
		&response.CreatedAt,
		&response.UpdatedAt,
		&editPerm,
		&sendPerm,
		&addPerm,
		&reqApproval,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Group not found", http.StatusNotFound)
			return
		}
		log.Printf("Error fetching group info: %v", err)
		http.Error(w, "Failed to fetch group info", http.StatusInternalServerError)
		return
	}

	if description.Valid {
		response.Description = description.String
	}
	if avatarURL.Valid {
		response.AvatarURL = avatarURL.String
	}

	response.EditGroupInfoPermission = "all_members"
	if editPerm.Valid && editPerm.String != "" {
		response.EditGroupInfoPermission = editPerm.String
	}
	response.SendMessagesPermission = "all_members"
	if sendPerm.Valid && sendPerm.String != "" {
		response.SendMessagesPermission = sendPerm.String
	}
	response.AddMembersPermission = "all_members"
	if addPerm.Valid && addPerm.String != "" {
		response.AddMembersPermission = addPerm.String
	}
	response.RequireAdminApproval = false
	if reqApproval.Valid {
		response.RequireAdminApproval = reqApproval.Bool
	}

	// Get group members with their roles
	rows, err := db.Query(`
		SELECT cm.profile_uid, p.username, p.profile_avatar_url, p.display_name, cm.role, cm.joined_at
		FROM conversation_members cm
		JOIN profiles p ON cm.profile_uid = p.firebase_uid
		WHERE cm.conversation_id = $1
		ORDER BY
			CASE cm.role
				WHEN 'owner' THEN 1
				WHEN 'admin' THEN 2
				ELSE 3
			END,
			cm.joined_at ASC
	`, groupID)

	if err != nil {
		log.Printf("Error fetching group members: %v", err)
		http.Error(w, "Failed to fetch group members", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	response.Members = make([]GroupMemberInfo, 0)
	for rows.Next() {
		var member GroupMemberInfo
		var avatarURL sql.NullString
		var displayName sql.NullString
		if err := rows.Scan(&member.UID, &member.Username, &avatarURL, &displayName, &member.Role, &member.JoinedAt); err != nil {
			log.Printf("Error scanning member: %v", err)
			continue
		}
		if avatarURL.Valid {
			member.AvatarURL = avatarURL.String
		}
		if displayName.Valid {
			member.DisplayName = displayName.String
		}
		response.Members = append(response.Members, member)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func addGroupMembersHandler(hub *Hub, w http.ResponseWriter, r *http.Request) {
	token, _, err := getVerifiedToken(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	currentUserUID := token.UID

	vars := mux.Vars(r)
	groupIDStr := vars["groupId"]
	groupID, err := strconv.Atoi(groupIDStr)
	if err != nil {
		http.Error(w, "Invalid group ID", http.StatusBadRequest)
		return
	}

	// Check if current user is member and check group permissions
	var userRole string
	var addPerm sql.NullString
	var reqApproval sql.NullBool
	err = db.QueryRow(`
		SELECT cm.role, c.add_members_permission, c.require_admin_approval
		FROM conversation_members cm
		JOIN conversations c ON cm.conversation_id = c.id
		WHERE cm.conversation_id = $1 AND cm.profile_uid = $2
	`, groupID, currentUserUID).Scan(&userRole, &addPerm, &reqApproval)

	if err != nil {
		http.Error(w, "Not a member of this group", http.StatusForbidden)
		return
	}

	isAdminOrOwner := userRole == "owner" || userRole == "admin"
	if addPerm.Valid && addPerm.String == "only_admins" && !isAdminOrOwner {
		http.Error(w, "Only admins can add members to this group", http.StatusForbidden)
		return
	}

	var payload AddGroupMembersPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if len(payload.MemberUsernames) == 0 {
		http.Error(w, "No members to add", http.StatusBadRequest)
		return
	}

	// Check current member count
	var currentMemberCount int
	err = db.QueryRow("SELECT COUNT(*) FROM conversation_members WHERE conversation_id = $1", groupID).Scan(&currentMemberCount)
	if err != nil {
		http.Error(w, "Failed to check member count", http.StatusInternalServerError)
		return
	}

	// Check if adding new members would exceed limit
	if currentMemberCount + len(payload.MemberUsernames) > MAX_GROUP_MEMBERS {
		http.Error(w, fmt.Sprintf("Cannot add members. Group limit is %d members (currently has %d)", MAX_GROUP_MEMBERS, currentMemberCount), http.StatusBadRequest)
		return
	}

	tx, err := db.Begin()
	if err != nil {
		http.Error(w, "Failed to start transaction", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	// Get UIDs from usernames (case-insensitive)
	query := "SELECT firebase_uid, username FROM profiles WHERE LOWER(username) = ANY($1)"

	// Convert usernames to lowercase for matching
	lowercaseUsernames := make([]string, len(payload.MemberUsernames))
	for i, username := range payload.MemberUsernames {
		lowercaseUsernames[i] = strings.ToLower(username)
	}

	rows, err := tx.Query(query, pq.Array(lowercaseUsernames))
	if err != nil {
		log.Printf("Failed to query profiles: %v", err)
		http.Error(w, "Failed to find members", http.StatusInternalServerError)
		return
	}

	foundUsernames := make(map[string]string) // username -> uid
	var candidateUIDs []string

	for rows.Next() {
		var uid, username string
		if err := rows.Scan(&uid, &username); err != nil {
			log.Printf("Failed to scan row: %v", err)
			continue
		}
		foundUsernames[username] = uid
		candidateUIDs = append(candidateUIDs, uid)
	}
	rows.Close() // Close rows before next query

	// Now check which candidates are NOT already members
	var memberUIDs []string
	for _, uid := range candidateUIDs {
		var exists bool
		err = tx.QueryRow(`
			SELECT EXISTS(
				SELECT 1 FROM conversation_members
				WHERE conversation_id = $1 AND profile_uid = $2
			)
		`, groupID, uid).Scan(&exists)

		if err != nil {
			log.Printf("Error checking membership for %s: %v", uid, err)
			continue
		}

		if !exists {
			memberUIDs = append(memberUIDs, uid)
			log.Printf("Will add user with UID %s to group %d", uid, groupID)
		} else {
			log.Printf("User with UID %s is already in group %d", uid, groupID)
		}
	}

	// Log which usernames were not found
	for _, requestedUsername := range payload.MemberUsernames {
		if _, found := foundUsernames[requestedUsername]; !found {
			log.Printf("Username not found in profiles: %s", requestedUsername)
		}
	}

	if len(memberUIDs) == 0 {
		log.Printf("No members to add. Requested: %v, Found: %v", payload.MemberUsernames, foundUsernames)
		http.Error(w, "All users are already members or not found", http.StatusBadRequest)
		return
	}

	// If admin approval is required and requester is not an admin, enqueue requests
	if reqApproval.Valid && reqApproval.Bool && !isAdminOrOwner {
		for _, uid := range memberUIDs {
			_, err = tx.Exec(`
				INSERT INTO group_join_requests (conversation_id, profile_uid, requested_by_uid, status, created_at)
				VALUES ($1, $2, $3, 'pending', NOW())
				ON CONFLICT (conversation_id, profile_uid) DO UPDATE
				SET status = 'pending', requested_by_uid = $3, created_at = NOW()
			`, groupID, uid, currentUserUID)
			if err != nil {
				log.Printf("Failed to create join request for %s: %v", uid, err)
			}
		}

		if err := tx.Commit(); err != nil {
			http.Error(w, "Failed to submit membership requests", http.StatusInternalServerError)
			return
		}

		// Notify admins of new pending requests
		adminRows, err := db.Query(`
			SELECT profile_uid FROM conversation_members
			WHERE conversation_id = $1 AND (role = 'owner' OR role = 'admin')
		`, groupID)
		if err == nil {
			var adminUIDs []string
			for adminRows.Next() {
				var aUID string
				if err := adminRows.Scan(&aUID); err == nil {
					adminUIDs = append(adminUIDs, aUID)
				}
			}
			adminRows.Close()
			if len(adminUIDs) > 0 {
				notificationPayload := map[string]interface{}{
					"type":            "group_join_requests_updated",
					"conversation_id": groupID,
				}
				notificationBytes, _ := json.Marshal(notificationPayload)
				hub.broadcast <- HubMessage{message: notificationBytes, recipients: adminUIDs}
			}
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message":           "Membership request submitted for admin approval",
			"pending_count":     len(memberUIDs),
			"requires_approval": true,
		})
		return
	}

	// Direct addition (if no approval required or requester is admin/owner)
	for _, uid := range memberUIDs {
		_, err = tx.Exec(`
			INSERT INTO conversation_members (conversation_id, profile_uid, role, joined_at)
			VALUES ($1, $2, 'member', NOW())
		`, groupID, uid)
		if err != nil {
			log.Printf("Failed to add member %s to group %d: %v", uid, groupID, err)
			http.Error(w, "Failed to add member", http.StatusInternalServerError)
			return
		}
	}

	// Update group's updated_at
	_, err = tx.Exec(`UPDATE conversations SET updated_at = NOW() WHERE id = $1`, groupID)
	if err != nil {
		log.Printf("Failed to update group timestamp: %v", err)
	}

	if err := tx.Commit(); err != nil {
		http.Error(w, "Failed to commit transaction", http.StatusInternalServerError)
		return
	}

	// 🔐 SECURITY: Rotate keys when new members are added
	// Get first added member UID for logging
	var firstAddedUID *string
	if len(memberUIDs) > 0 {
		firstAddedUID = &memberUIDs[0]
	}
	if err := triggerKeyRotation(db, groupID, "member_added", currentUserUID, firstAddedUID); err != nil {
		log.Printf("Failed to rotate keys after member addition: %v", err)
		// Don't fail the request, members already added
	}

	// Broadcast update to all members
	allMemberUIDs, err := getConversationMemberUIDs(db, groupID)
	if err == nil {
		notificationPayload := map[string]interface{}{
			"type": "conversation_update",
			"conversation_id": groupID,
			"key_rotation_required": true,
			"reason": "member_added",
		}
		notificationBytes, _ := json.Marshal(notificationPayload)
		hub.broadcast <- HubMessage{message: notificationBytes, recipients: allMemberUIDs}
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Members added successfully",
		"added_count": len(memberUIDs),
	})
}

func removeGroupMemberHandler(hub *Hub, w http.ResponseWriter, r *http.Request) {
	token, _, err := getVerifiedToken(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	currentUserUID := token.UID

	vars := mux.Vars(r)
	groupIDStr := vars["groupId"]
	groupID, err := strconv.Atoi(groupIDStr)
	if err != nil {
		http.Error(w, "Invalid group ID", http.StatusBadRequest)
		return
	}

	// Check if current user is owner or admin
	var userRole string
	err = db.QueryRow(`
		SELECT role FROM conversation_members
		WHERE conversation_id = $1 AND profile_uid = $2
	`, groupID, currentUserUID).Scan(&userRole)

	if err != nil {
		http.Error(w, "Not a member of this group", http.StatusForbidden)
		return
	}

	if userRole != "owner" && userRole != "admin" {
		http.Error(w, "Only owners and admins can remove members", http.StatusForbidden)
		return
	}

	var payload RemoveGroupMemberPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Check if target member's role
	var targetRole string
	err = db.QueryRow(`
		SELECT role FROM conversation_members
		WHERE conversation_id = $1 AND profile_uid = $2
	`, groupID, payload.MemberUID).Scan(&targetRole)

	if err != nil {
		http.Error(w, "Member not found in group", http.StatusNotFound)
		return
	}

	// Cannot remove owner
	if targetRole == "owner" {
		http.Error(w, "Cannot remove group owner", http.StatusForbidden)
		return
	}

	// Only owner can remove admin
	if targetRole == "admin" && userRole != "owner" {
		http.Error(w, "Only owner can remove admins", http.StatusForbidden)
		return
	}

	// Remove member
	result, err := db.Exec(`
		DELETE FROM conversation_members
		WHERE conversation_id = $1 AND profile_uid = $2
	`, groupID, payload.MemberUID)

	if err != nil {
		http.Error(w, "Failed to remove member", http.StatusInternalServerError)
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		http.Error(w, "Member not found", http.StatusNotFound)
		return
	}

	// Update group's updated_at
	db.Exec(`UPDATE conversations SET updated_at = NOW() WHERE id = $1`, groupID)

	// 🔐 SECURITY: Rotate keys when member is removed
	if err := triggerKeyRotation(db, groupID, "member_removed", currentUserUID, &payload.MemberUID); err != nil {
		log.Printf("Failed to rotate keys after member removal: %v", err)
		// Don't fail the request, member already removed
	}

	// Broadcast update to remaining members
	allMemberUIDs, err := getConversationMemberUIDs(db, groupID)
	if err == nil {
		notificationPayload := map[string]interface{}{
			"type": "conversation_update",
			"conversation_id": groupID,
			"key_rotation_required": true,
			"reason": "member_removed",
		}
		notificationBytes, _ := json.Marshal(notificationPayload)
		hub.broadcast <- HubMessage{message: notificationBytes, recipients: allMemberUIDs}
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Member removed successfully",
	})
}

func changeGroupMemberRoleHandler(hub *Hub, w http.ResponseWriter, r *http.Request) {
	token, _, err := getVerifiedToken(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	currentUserUID := token.UID

	vars := mux.Vars(r)
	groupIDStr := vars["groupId"]
	groupID, err := strconv.Atoi(groupIDStr)
	if err != nil {
		http.Error(w, "Invalid group ID", http.StatusBadRequest)
		return
	}

	// Check if current user is owner
	var userRole string
	err = db.QueryRow(`
		SELECT role FROM conversation_members
		WHERE conversation_id = $1 AND profile_uid = $2
	`, groupID, currentUserUID).Scan(&userRole)

	if err != nil {
		http.Error(w, "Not a member of this group", http.StatusForbidden)
		return
	}

	if userRole != "owner" && userRole != "admin" {
		http.Error(w, "Only the group owner and admins can change member roles", http.StatusForbidden)
		return
	}

	var payload ChangeGroupMemberRolePayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate new role
	if payload.NewRole != "admin" && payload.NewRole != "member" {
		http.Error(w, "Invalid role. Must be 'admin' or 'member'", http.StatusBadRequest)
		return
	}

	// Check if target member exists and get their current role
	var currentRole string
	err = db.QueryRow(`
		SELECT role FROM conversation_members
		WHERE conversation_id = $1 AND profile_uid = $2
	`, groupID, payload.MemberUID).Scan(&currentRole)

	if err != nil {
		http.Error(w, "Member not found in group", http.StatusNotFound)
		return
	}

	// Cannot change owner's role
	if currentRole == "owner" {
		http.Error(w, "Cannot change the owner's role", http.StatusForbidden)
		return
	}

	// Only owner can demote an admin to member
	if currentRole == "admin" && payload.NewRole == "member" && userRole != "owner" {
		http.Error(w, "Only the group owner can dismiss other admins", http.StatusForbidden)
		return
	}

	// Cannot change own role
	if payload.MemberUID == currentUserUID {
		http.Error(w, "Cannot change your own role", http.StatusForbidden)
		return
	}

	// Update member role
	result, err := db.Exec(`
		UPDATE conversation_members
		SET role = $1
		WHERE conversation_id = $2 AND profile_uid = $3
	`, payload.NewRole, groupID, payload.MemberUID)

	if err != nil {
		log.Printf("Error updating member role: %v", err)
		http.Error(w, "Failed to update member role", http.StatusInternalServerError)
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		http.Error(w, "Member not found", http.StatusNotFound)
		return
	}

	// Update group's updated_at
	db.Exec(`UPDATE conversations SET updated_at = NOW() WHERE id = $1`, groupID)

	// Broadcast update to all members
	allMemberUIDs, err := getConversationMemberUIDs(db, groupID)
	if err == nil {
		notificationPayload := map[string]string{"type": "conversation_update"}
		notificationBytes, _ := json.Marshal(notificationPayload)
		hub.broadcast <- HubMessage{message: notificationBytes, recipients: allMemberUIDs}
	}

	action := "promoted to admin"
	if payload.NewRole == "member" {
		action = "demoted to member"
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": fmt.Sprintf("Member %s", action),
	})
}

func updateGroupAvatarHandler(hub *Hub, w http.ResponseWriter, r *http.Request) {
	token, _, err := getVerifiedToken(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	currentUserUID := token.UID

	vars := mux.Vars(r)
	groupIDStr := vars["groupId"]
	groupID, err := strconv.Atoi(groupIDStr)
	if err != nil {
		http.Error(w, "Invalid group ID", http.StatusBadRequest)
		return
	}

	// Check if current user is member and check edit permission
	var userRole string
	var editPerm sql.NullString
	err = db.QueryRow(`
		SELECT cm.role, c.edit_group_info_permission
		FROM conversation_members cm
		JOIN conversations c ON cm.conversation_id = c.id
		WHERE cm.conversation_id = $1 AND cm.profile_uid = $2
	`, groupID, currentUserUID).Scan(&userRole, &editPerm)

	if err != nil {
		http.Error(w, "Not a member of this group", http.StatusForbidden)
		return
	}

	isAdminOrOwner := userRole == "owner" || userRole == "admin"
	if editPerm.Valid && editPerm.String == "only_admins" && !isAdminOrOwner {
		http.Error(w, "Only admins can change the group avatar", http.StatusForbidden)
		return
	}

	var payload UpdateGroupAvatarPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if payload.AvatarURL == "" {
		http.Error(w, "Avatar URL is required", http.StatusBadRequest)
		return
	}

	// Update group avatar
	result, err := db.Exec(`
		UPDATE conversations
		SET group_avatar_url = $1, updated_at = NOW()
		WHERE id = $2 AND is_group = true
	`, payload.AvatarURL, groupID)

	if err != nil {
		log.Printf("Error updating group avatar: %v", err)
		http.Error(w, "Failed to update group avatar", http.StatusInternalServerError)
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		http.Error(w, "Group not found", http.StatusNotFound)
		return
	}

	// Broadcast update to all members
	allMemberUIDs, err := getConversationMemberUIDs(db, groupID)
	if err == nil {
		notificationPayload := map[string]string{"type": "conversation_update"}
		notificationBytes, _ := json.Marshal(notificationPayload)
		hub.broadcast <- HubMessage{message: notificationBytes, recipients: allMemberUIDs}
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Group avatar updated successfully",
		"avatarUrl": payload.AvatarURL,
	})
}

func updateGroupInfoHandler(hub *Hub, w http.ResponseWriter, r *http.Request) {
	token, _, err := getVerifiedToken(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	currentUserUID := token.UID

	vars := mux.Vars(r)
	groupIDStr := vars["groupId"]
	groupID, err := strconv.Atoi(groupIDStr)
	if err != nil {
		http.Error(w, "Invalid group ID", http.StatusBadRequest)
		return
	}

	// Check if current user is member and check edit permission
	var userRole string
	var editPerm sql.NullString
	err = db.QueryRow(`
		SELECT cm.role, c.edit_group_info_permission
		FROM conversation_members cm
		JOIN conversations c ON cm.conversation_id = c.id
		WHERE cm.conversation_id = $1 AND cm.profile_uid = $2
	`, groupID, currentUserUID).Scan(&userRole, &editPerm)

	if err != nil {
		http.Error(w, "Not a member of this group", http.StatusForbidden)
		return
	}

	isAdminOrOwner := userRole == "owner" || userRole == "admin"
	if editPerm.Valid && editPerm.String == "only_admins" && !isAdminOrOwner {
		http.Error(w, "Only admins can edit group info", http.StatusForbidden)
		return
	}

	var payload UpdateGroupInfoPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Build dynamic update query
	updates := []string{}
	args := []interface{}{}
	argCount := 1

	if payload.GroupName != "" {
		updates = append(updates, fmt.Sprintf("group_name = $%d", argCount))
		args = append(args, strings.TrimSpace(payload.GroupName))
		argCount++
	}

	if payload.Description != "" {
		updates = append(updates, fmt.Sprintf("description = $%d", argCount))
		args = append(args, strings.TrimSpace(payload.Description))
		argCount++
	}

	if len(updates) == 0 {
		http.Error(w, "No fields to update", http.StatusBadRequest)
		return
	}

	updates = append(updates, fmt.Sprintf("updated_at = NOW()"))
	args = append(args, groupID)

	query := fmt.Sprintf("UPDATE conversations SET %s WHERE id = $%d AND is_group = true",
		strings.Join(updates, ", "), argCount)

	result, err := db.Exec(query, args...)
	if err != nil {
		log.Printf("Error updating group info: %v", err)
		http.Error(w, "Failed to update group info", http.StatusInternalServerError)
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		http.Error(w, "Group not found", http.StatusNotFound)
		return
	}

	// Broadcast update to all members
	allMemberUIDs, err := getConversationMemberUIDs(db, groupID)
	if err == nil {
		notificationPayload := map[string]string{"type": "conversation_update"}
		notificationBytes, _ := json.Marshal(notificationPayload)
		hub.broadcast <- HubMessage{message: notificationBytes, recipients: allMemberUIDs}
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Group info updated successfully",
	})
}

// initGroupPermissionsSchema ensures database tables and columns for group permissions exist
func initGroupPermissionsSchema(db *sql.DB) {
	queries := []string{
		`ALTER TABLE conversations ADD COLUMN IF NOT EXISTS edit_group_info_permission VARCHAR(20) DEFAULT 'all_members'`,
		`ALTER TABLE conversations ADD COLUMN IF NOT EXISTS send_messages_permission VARCHAR(20) DEFAULT 'all_members'`,
		`ALTER TABLE conversations ADD COLUMN IF NOT EXISTS add_members_permission VARCHAR(20) DEFAULT 'all_members'`,
		`ALTER TABLE conversations ADD COLUMN IF NOT EXISTS require_admin_approval BOOLEAN DEFAULT false`,
		`CREATE TABLE IF NOT EXISTS group_join_requests (
			id SERIAL PRIMARY KEY,
			conversation_id INT REFERENCES conversations(id) ON DELETE CASCADE,
			profile_uid VARCHAR(128) REFERENCES profiles(firebase_uid) ON DELETE CASCADE,
			requested_by_uid VARCHAR(128) REFERENCES profiles(firebase_uid) ON DELETE CASCADE,
			status VARCHAR(20) DEFAULT 'pending',
			created_at TIMESTAMP DEFAULT NOW(),
			reviewed_by_uid VARCHAR(128),
			reviewed_at TIMESTAMP,
			UNIQUE(conversation_id, profile_uid)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_group_join_requests_conv ON group_join_requests(conversation_id, status)`,
	}
	for _, q := range queries {
		if _, err := db.Exec(q); err != nil {
			log.Printf("Notice: initGroupPermissionsSchema query execution: %v", err)
		}
	}
	log.Println("Group permissions schema verified")
}

func getGroupPermissionsHandler(w http.ResponseWriter, r *http.Request) {
	token, _, err := getVerifiedToken(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	currentUserUID := token.UID

	vars := mux.Vars(r)
	groupID, err := strconv.Atoi(vars["groupId"])
	if err != nil {
		http.Error(w, "Invalid group ID", http.StatusBadRequest)
		return
	}

	var isMember bool
	err = db.QueryRow(`
		SELECT EXISTS(SELECT 1 FROM conversation_members WHERE conversation_id = $1 AND profile_uid = $2)
	`, groupID, currentUserUID).Scan(&isMember)
	if err != nil || !isMember {
		http.Error(w, "Not a member of this group", http.StatusForbidden)
		return
	}

	var resp GroupPermissionsResponse
	var editPerm, sendPerm, addPerm sql.NullString
	var reqApproval sql.NullBool
	err = db.QueryRow(`
		SELECT
			COALESCE(edit_group_info_permission, 'all_members'),
			COALESCE(send_messages_permission, 'all_members'),
			COALESCE(add_members_permission, 'all_members'),
			COALESCE(require_admin_approval, false)
		FROM conversations
		WHERE id = $1 AND is_group = true
	`, groupID).Scan(
		&editPerm,
		&sendPerm,
		&addPerm,
		&reqApproval,
	)
	if err != nil {
		http.Error(w, "Failed to fetch permissions", http.StatusInternalServerError)
		return
	}

	resp.EditGroupInfoPermission = "all_members"
	if editPerm.Valid && editPerm.String != "" {
		resp.EditGroupInfoPermission = editPerm.String
	}
	resp.SendMessagesPermission = "all_members"
	if sendPerm.Valid && sendPerm.String != "" {
		resp.SendMessagesPermission = sendPerm.String
	}
	resp.AddMembersPermission = "all_members"
	if addPerm.Valid && addPerm.String != "" {
		resp.AddMembersPermission = addPerm.String
	}
	resp.RequireAdminApproval = false
	if reqApproval.Valid {
		resp.RequireAdminApproval = reqApproval.Bool
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func updateGroupPermissionsHandler(hub *Hub, w http.ResponseWriter, r *http.Request) {
	token, _, err := getVerifiedToken(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	currentUserUID := token.UID

	vars := mux.Vars(r)
	groupID, err := strconv.Atoi(vars["groupId"])
	if err != nil {
		http.Error(w, "Invalid group ID", http.StatusBadRequest)
		return
	}

	var userRole string
	err = db.QueryRow(`
		SELECT role FROM conversation_members
		WHERE conversation_id = $1 AND profile_uid = $2
	`, groupID, currentUserUID).Scan(&userRole)
	if err != nil || (userRole != "owner" && userRole != "admin") {
		http.Error(w, "Only owner and admins can update group permissions", http.StatusForbidden)
		return
	}

	var payload UpdateGroupPermissionsPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var updates []string
	var args []interface{}
	argCount := 1

	if payload.EditGroupInfoPermission != nil {
		val := *payload.EditGroupInfoPermission
		if val == "all_members" || val == "only_admins" {
			updates = append(updates, fmt.Sprintf("edit_group_info_permission = $%d", argCount))
			args = append(args, val)
			argCount++
		}
	}
	if payload.SendMessagesPermission != nil {
		val := *payload.SendMessagesPermission
		if val == "all_members" || val == "only_admins" {
			updates = append(updates, fmt.Sprintf("send_messages_permission = $%d", argCount))
			args = append(args, val)
			argCount++
		}
	}
	if payload.AddMembersPermission != nil {
		val := *payload.AddMembersPermission
		if val == "all_members" || val == "only_admins" {
			updates = append(updates, fmt.Sprintf("add_members_permission = $%d", argCount))
			args = append(args, val)
			argCount++
		}
	}
	if payload.RequireAdminApproval != nil {
		if !*payload.RequireAdminApproval {
			var pendingCount int
			err = db.QueryRow("SELECT COUNT(*) FROM group_join_requests WHERE conversation_id = $1 AND status = 'pending'", groupID).Scan(&pendingCount)
			if err == nil && pendingCount > 0 {
				http.Error(w, "Cannot disable admin approval while there are pending join requests. Please approve or deny all pending requests first.", http.StatusBadRequest)
				return
			}
		}
		updates = append(updates, fmt.Sprintf("require_admin_approval = $%d", argCount))
		args = append(args, *payload.RequireAdminApproval)
		argCount++
	}

	if len(updates) > 0 {
		args = append(args, groupID)
		query := fmt.Sprintf("UPDATE conversations SET %s, updated_at = NOW() WHERE id = $%d AND is_group = true",
			strings.Join(updates, ", "), argCount)
		if _, err := db.Exec(query, args...); err != nil {
			log.Printf("Error updating group permissions: %v", err)
			http.Error(w, "Failed to update permissions", http.StatusInternalServerError)
			return
		}
	}

	// Broadcast permissions update to all group members
	allMemberUIDs, err := getConversationMemberUIDs(db, groupID)
	if err == nil {
		notifPayload := map[string]interface{}{
			"type":            "group_permissions_updated",
			"conversation_id": groupID,
		}
		notifBytes, _ := json.Marshal(notifPayload)
		hub.broadcast <- HubMessage{message: notifBytes, recipients: allMemberUIDs}
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Permissions updated successfully"})
}

func getGroupJoinRequestsHandler(w http.ResponseWriter, r *http.Request) {
	token, _, err := getVerifiedToken(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	currentUserUID := token.UID

	vars := mux.Vars(r)
	groupID, err := strconv.Atoi(vars["groupId"])
	if err != nil {
		http.Error(w, "Invalid group ID", http.StatusBadRequest)
		return
	}

	var userRole string
	err = db.QueryRow(`
		SELECT role FROM conversation_members
		WHERE conversation_id = $1 AND profile_uid = $2
	`, groupID, currentUserUID).Scan(&userRole)
	if err != nil || (userRole != "owner" && userRole != "admin") {
		http.Error(w, "Only owner and admins can view join requests", http.StatusForbidden)
		return
	}

	rows, err := db.Query(`
		SELECT jr.id, jr.conversation_id, jr.profile_uid, p.username, p.display_name, p.profile_avatar_url,
		       COALESCE(p_req.username, jr.requested_by_uid), jr.status, jr.created_at
		FROM group_join_requests jr
		JOIN profiles p ON jr.profile_uid = p.firebase_uid
		LEFT JOIN profiles p_req ON jr.requested_by_uid = p_req.firebase_uid
		WHERE jr.conversation_id = $1 AND jr.status = 'pending'
		ORDER BY jr.created_at ASC
	`, groupID)
	if err != nil {
		log.Printf("Error fetching join requests: %v", err)
		http.Error(w, "Failed to fetch join requests", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	requests := make([]GroupJoinRequestInfo, 0)
	for rows.Next() {
		var req GroupJoinRequestInfo
		var displayName sql.NullString
		var avatarURL sql.NullString
		if err := rows.Scan(&req.ID, &req.GroupID, &req.ProfileUID, &req.Username, &displayName, &avatarURL, &req.RequestedBy, &req.Status, &req.CreatedAt); err != nil {
			continue
		}
		if displayName.Valid {
			req.DisplayName = displayName.String
		}
		if avatarURL.Valid {
			req.AvatarURL = &avatarURL.String
		}
		requests = append(requests, req)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(requests)
}

func reviewGroupJoinRequestHandler(hub *Hub, w http.ResponseWriter, r *http.Request) {
	token, _, err := getVerifiedToken(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	currentUserUID := token.UID

	vars := mux.Vars(r)
	groupID, err := strconv.Atoi(vars["groupId"])
	requestID, err2 := strconv.Atoi(vars["requestId"])
	if err != nil || err2 != nil {
		http.Error(w, "Invalid parameters", http.StatusBadRequest)
		return
	}

	var userRole string
	err = db.QueryRow(`
		SELECT role FROM conversation_members
		WHERE conversation_id = $1 AND profile_uid = $2
	`, groupID, currentUserUID).Scan(&userRole)
	if err != nil || (userRole != "owner" && userRole != "admin") {
		http.Error(w, "Only owner and admins can review join requests", http.StatusForbidden)
		return
	}

	var payload ReviewJoinRequestPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if payload.Action != "approve" && payload.Action != "reject" {
		http.Error(w, "Action must be 'approve' or 'reject'", http.StatusBadRequest)
		return
	}

	var candidateUID string
	err = db.QueryRow(`
		SELECT profile_uid FROM group_join_requests
		WHERE id = $1 AND conversation_id = $2 AND status = 'pending'
	`, requestID, groupID).Scan(&candidateUID)
	if err != nil {
		http.Error(w, "Join request not found or already processed", http.StatusNotFound)
		return
	}

	tx, err := db.Begin()
	if err != nil {
		http.Error(w, "Transaction start failed", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	if payload.Action == "approve" {
		_, err = tx.Exec(`
			INSERT INTO conversation_members (conversation_id, profile_uid, role, joined_at)
			VALUES ($1, $2, 'member', NOW())
			ON CONFLICT (conversation_id, profile_uid) DO NOTHING
		`, groupID, candidateUID)
		if err != nil {
			log.Printf("Failed to insert approved member: %v", err)
			http.Error(w, "Failed to add member", http.StatusInternalServerError)
			return
		}
		_, err = tx.Exec(`
			UPDATE group_join_requests
			SET status = 'approved', reviewed_by_uid = $1, reviewed_at = NOW()
			WHERE id = $2
		`, currentUserUID, requestID)
	} else {
		_, err = tx.Exec(`
			UPDATE group_join_requests
			SET status = 'rejected', reviewed_by_uid = $1, reviewed_at = NOW()
			WHERE id = $2
		`, currentUserUID, requestID)
	}

	if err != nil {
		http.Error(w, "Failed to update request status", http.StatusInternalServerError)
		return
	}

	if err := tx.Commit(); err != nil {
		http.Error(w, "Commit failed", http.StatusInternalServerError)
		return
	}

	if payload.Action == "approve" {
		_ = triggerKeyRotation(db, groupID, "member_added", currentUserUID, &candidateUID)
		allMemberUIDs, err := getConversationMemberUIDs(db, groupID)
		if err == nil {
			notifPayload := map[string]interface{}{
				"type":                  "conversation_update",
				"conversation_id":       groupID,
				"key_rotation_required": true,
				"reason":                "member_added",
			}
			notifBytes, _ := json.Marshal(notifPayload)
			hub.broadcast <- HubMessage{message: notifBytes, recipients: allMemberUIDs}
		}
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": fmt.Sprintf("Join request %sd", payload.Action),
	})
}

func batchReviewGroupJoinRequestsHandler(hub *Hub, w http.ResponseWriter, r *http.Request) {
	token, _, err := getVerifiedToken(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	currentUserUID := token.UID

	vars := mux.Vars(r)
	groupID, err := strconv.Atoi(vars["groupId"])
	if err != nil {
		http.Error(w, "Invalid parameters", http.StatusBadRequest)
		return
	}

	var userRole string
	err = db.QueryRow(`
		SELECT role FROM conversation_members
		WHERE conversation_id = $1 AND profile_uid = $2
	`, groupID, currentUserUID).Scan(&userRole)
	if err != nil || (userRole != "owner" && userRole != "admin") {
		http.Error(w, "Only owner and admins can review join requests", http.StatusForbidden)
		return
	}

	var payload BatchReviewJoinRequestsPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if payload.Action != "approve_all" && payload.Action != "reject_all" {
		http.Error(w, "Action must be 'approve_all' or 'reject_all'", http.StatusBadRequest)
		return
	}

	// Fetch all pending candidate UIDs
	rows, err := db.Query(`
		SELECT profile_uid FROM group_join_requests
		WHERE conversation_id = $1 AND status = 'pending'
	`, groupID)
	if err != nil {
		http.Error(w, "Failed to query pending requests", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var candidateUIDs []string
	for rows.Next() {
		var uid string
		if err := rows.Scan(&uid); err == nil {
			candidateUIDs = append(candidateUIDs, uid)
		}
	}

	tx, err := db.Begin()
	if err != nil {
		http.Error(w, "Transaction start failed", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	if payload.Action == "approve_all" {
		for _, uid := range candidateUIDs {
			_, _ = tx.Exec(`
				INSERT INTO conversation_members (conversation_id, profile_uid, role, joined_at)
				VALUES ($1, $2, 'member', NOW())
				ON CONFLICT (conversation_id, profile_uid) DO NOTHING
			`, groupID, uid)
		}
		_, err = tx.Exec(`
			UPDATE group_join_requests
			SET status = 'approved', reviewed_by_uid = $1, reviewed_at = NOW()
			WHERE conversation_id = $2 AND status = 'pending'
		`, currentUserUID, groupID)
	} else {
		_, err = tx.Exec(`
			UPDATE group_join_requests
			SET status = 'rejected', reviewed_by_uid = $1, reviewed_at = NOW()
			WHERE conversation_id = $2 AND status = 'pending'
		`, currentUserUID, groupID)
	}

	if err != nil {
		http.Error(w, "Failed to update requests status", http.StatusInternalServerError)
		return
	}

	// If disableApproval is requested, also update require_admin_approval to false
	if payload.DisableApproval {
		_, err = tx.Exec(`
			UPDATE conversations
			SET require_admin_approval = false, updated_at = NOW()
			WHERE id = $1 AND is_group = true
		`, groupID)
		if err != nil {
			http.Error(w, "Failed to disable admin approval", http.StatusInternalServerError)
			return
		}
	}

	if err := tx.Commit(); err != nil {
		http.Error(w, "Commit failed", http.StatusInternalServerError)
		return
	}

	// Broadcast updates
	allMemberUIDs, err := getConversationMemberUIDs(db, groupID)
	if err == nil {
		if payload.Action == "approve_all" {
			for _, uid := range candidateUIDs {
				_ = triggerKeyRotation(db, groupID, "member_added", currentUserUID, &uid)
			}
			notifPayload := map[string]interface{}{
				"type":                  "conversation_update",
				"conversation_id":       groupID,
				"key_rotation_required": true,
				"reason":                "member_added",
			}
			notifBytes, _ := json.Marshal(notifPayload)
			hub.broadcast <- HubMessage{message: notifBytes, recipients: allMemberUIDs}
		}

		if payload.DisableApproval {
			permPayload := map[string]interface{}{
				"type":            "group_permissions_updated",
				"conversation_id": groupID,
			}
			permBytes, _ := json.Marshal(permPayload)
			hub.broadcast <- HubMessage{message: permBytes, recipients: allMemberUIDs}
		}
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": fmt.Sprintf("All requests %sd successfully", payload.Action),
		"count":   len(candidateUIDs),
	})
}

func transferGroupOwnershipHandler(hub *Hub, w http.ResponseWriter, r *http.Request) {
	token, _, err := getVerifiedToken(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	currentUserUID := token.UID

	vars := mux.Vars(r)
	groupID, err := strconv.Atoi(vars["groupId"])
	if err != nil {
		http.Error(w, "Invalid group ID", http.StatusBadRequest)
		return
	}

	var userRole string
	err = db.QueryRow(`
		SELECT role FROM conversation_members
		WHERE conversation_id = $1 AND profile_uid = $2
	`, groupID, currentUserUID).Scan(&userRole)
	if err != nil || userRole != "owner" {
		http.Error(w, "Only the current group owner can transfer ownership", http.StatusForbidden)
		return
	}

	var payload TransferOwnershipPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if payload.NewOwnerUID == "" || payload.NewOwnerUID == currentUserUID {
		http.Error(w, "Invalid new owner UID", http.StatusBadRequest)
		return
	}

	var targetExists bool
	err = db.QueryRow(`
		SELECT EXISTS(
			SELECT 1 FROM conversation_members WHERE conversation_id = $1 AND profile_uid = $2
		)
	`, groupID, payload.NewOwnerUID).Scan(&targetExists)
	if err != nil || !targetExists {
		http.Error(w, "Target user is not a member of this group", http.StatusBadRequest)
		return
	}

	tx, err := db.Begin()
	if err != nil {
		http.Error(w, "Failed to begin transaction", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	_, err = tx.Exec(`UPDATE conversations SET creator_uid = $1, updated_at = NOW() WHERE id = $2`, payload.NewOwnerUID, groupID)
	if err != nil {
		http.Error(w, "Failed to update group creator", http.StatusInternalServerError)
		return
	}

	_, err = tx.Exec(`UPDATE conversation_members SET role = 'admin' WHERE conversation_id = $1 AND profile_uid = $2`, groupID, currentUserUID)
	if err != nil {
		http.Error(w, "Failed to update previous owner role", http.StatusInternalServerError)
		return
	}

	_, err = tx.Exec(`UPDATE conversation_members SET role = 'owner' WHERE conversation_id = $1 AND profile_uid = $2`, groupID, payload.NewOwnerUID)
	if err != nil {
		http.Error(w, "Failed to update new owner role", http.StatusInternalServerError)
		return
	}

	if err := tx.Commit(); err != nil {
		http.Error(w, "Failed to commit ownership transfer", http.StatusInternalServerError)
		return
	}

	allMemberUIDs, err := getConversationMemberUIDs(db, groupID)
	if err == nil {
		notifPayload := map[string]interface{}{
			"type":            "conversation_update",
			"conversation_id": groupID,
		}
		notifBytes, _ := json.Marshal(notifPayload)
		hub.broadcast <- HubMessage{message: notifBytes, recipients: allMemberUIDs}
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Ownership transferred successfully",
	})
}

func leaveGroupHandler(hub *Hub, w http.ResponseWriter, r *http.Request) {
	token, _, err := getVerifiedToken(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	currentUserUID := token.UID

	vars := mux.Vars(r)
	idStr := vars["groupId"]
	conversationID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid group ID", http.StatusBadRequest)
		return
	}

	var isGroup bool
	var creatorUID sql.NullString
	err = db.QueryRow("SELECT is_group, creator_uid FROM conversations WHERE id = $1", conversationID).Scan(&isGroup, &creatorUID)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Group not found", http.StatusNotFound)
			return
		}
		log.Printf("DB error checking group details for ID %d: %v", conversationID, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if !isGroup {
		http.Error(w, "Not a group conversation", http.StatusBadRequest)
		return
	}

	var memberCount int
	err = db.QueryRow("SELECT COUNT(*) FROM conversation_members WHERE conversation_id = $1 AND profile_uid = $2", conversationID, currentUserUID).Scan(&memberCount)
	if err != nil || memberCount == 0 {
		http.Error(w, "Forbidden: Not a member of this group", http.StatusForbidden)
		return
	}

	tx, err := db.Begin()
	if err != nil {
		log.Printf("Failed to start transaction for leaving group: %v", err)
		http.Error(w, "Failed to leave group (transaction error)", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	_, err = tx.Exec("DELETE FROM conversation_members WHERE conversation_id = $1 AND profile_uid = $2", conversationID, currentUserUID)
	if err != nil {
		log.Printf("DB error removing member %s from group %d: %v", currentUserUID, conversationID, err)
		http.Error(w, "Failed to leave group", http.StatusInternalServerError)
		return
	}

	var remainingMembers int
	err = tx.QueryRow("SELECT COUNT(*) FROM conversation_members WHERE conversation_id = $1", conversationID).Scan(&remainingMembers)
	if err != nil {
		log.Printf("DB error counting remaining members for group %d: %v", conversationID, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if remainingMembers == 0 {
		log.Printf("Last member %s leaving group %d. Deleting empty group.", currentUserUID, conversationID)
		_, err = tx.Exec("DELETE FROM messages WHERE conversation_id = $1", conversationID)
		if err != nil {
			http.Error(w, "Failed to delete empty group messages", http.StatusInternalServerError)
			return
		}
		_, err = tx.Exec("DELETE FROM conversations WHERE id = $1", conversationID)
		if err != nil {
			http.Error(w, "Failed to delete empty group", http.StatusInternalServerError)
			return
		}
	} else if creatorUID.Valid && creatorUID.String == currentUserUID {
		// Group creator/owner left! Automatically elect oldest admin or oldest member as new owner
		var successorUID string
		err = tx.QueryRow(`
			SELECT profile_uid FROM conversation_members
			WHERE conversation_id = $1 AND role = 'admin'
			ORDER BY joined_at ASC LIMIT 1
		`, conversationID).Scan(&successorUID)
		if err != nil || successorUID == "" {
			_ = tx.QueryRow(`
				SELECT profile_uid FROM conversation_members
				WHERE conversation_id = $1
				ORDER BY joined_at ASC LIMIT 1
			`, conversationID).Scan(&successorUID)
		}
		if successorUID != "" {
			_, _ = tx.Exec(`UPDATE conversation_members SET role = 'owner' WHERE conversation_id = $1 AND profile_uid = $2`, conversationID, successorUID)
			_, _ = tx.Exec(`UPDATE conversations SET creator_uid = $1 WHERE id = $2`, successorUID, conversationID)
			log.Printf("Group %d creator left. Transferred ownership to successor %s", conversationID, successorUID)
		}
	}

	if err := tx.Commit(); err != nil {
		log.Printf("Failed to commit leave group transaction: %v", err)
		http.Error(w, "Failed to leave group (commit error)", http.StatusInternalServerError)
		return
	}

	log.Printf("User %s left group %d", currentUserUID, conversationID)

	// 🔐 SECURITY: Rotate keys when member leaves (only if group still exists)
	if remainingMembers > 0 {
		if err := triggerKeyRotation(db, int(conversationID), "member_left", currentUserUID, &currentUserUID); err != nil {
			log.Printf("Failed to rotate keys after member left: %v", err)
			// Don't fail the request, member already left
		}
	}

	var recipientUIDs []string
	if remainingMembers > 0 {
		rows, err := db.Query("SELECT cm.profile_uid FROM conversation_members cm WHERE cm.conversation_id = $1", conversationID)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var uid string
				if err := rows.Scan(&uid); err == nil {
					recipientUIDs = append(recipientUIDs, uid)
				}
			}
		}
	}

	recipientUIDs = append(recipientUIDs, currentUserUID)

	notificationPayload := map[string]interface{}{
		"type": "conversation_update",
		"conversation_id": int(conversationID),
		"key_rotation_required": remainingMembers > 0,
		"reason": "member_left",
	}
	notificationBytes, _ := json.Marshal(notificationPayload)
	hub.broadcast <- HubMessage{message: notificationBytes, recipients: recipientUIDs}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Successfully left group %d", conversationID)
}


// Basic rate limiting middleware (optional but recommended)
func basicRateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // You can implement simple rate limiting here if needed
        // For now, just pass through
        next(w, r)
    }
}


func serveWs(hub *Hub, db *sql.DB, w http.ResponseWriter, r *http.Request) {
	// Authenticate the websocket request (verifies Firebase token)
	token, err := getVerifiedTokenForWs(r)
	if err != nil {
		log.Printf("serveWs: Unauthenticated connection attempt: %v", err)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	uid := token.UID

	// Lookup username (optional: fallback to UID if not found)
	var username string
	err = db.QueryRow("SELECT username FROM profiles WHERE firebase_uid = $1", uid).Scan(&username)
	if err != nil {
		log.Printf("serveWs: Could not find profile for UID %s: %v", uid, err)
		// treat missing profile as unauthorized
		http.Error(w, "profile not found", http.StatusForbidden)
		return
	}

	// Upgrade HTTP -> WebSocket
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("serveWs: upgrade failed for uid=%s username=%s: %v", uid, username, err)
		return
	}

	// Create client and register to hub
	client := &Client{
		hub:      hub,
		conn:     conn,
		send:     make(chan []byte, 256),
		username: username,
		uid:      uid,
		db:       db,
	}

	log.Printf("serveWs: registering client username=%s uid=%s", client.username, client.uid)
	client.hub.register <- client
	go deliverOfflineMessages(client)

	// Start pumps: writer goroutine and reader goroutine.
	// readPump will unregister on exit (defer in readPump does hub.unregister <- c)
	go client.writePump()
	go client.readPump()
}

// Add this handler function
func getConversationMembersHandler(w http.ResponseWriter, r *http.Request, conversationIDStr string) {
    if r.Method != http.MethodGet {
        http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
        return
    }

    // Authenticate request
    token, _, err := getVerifiedToken(r)
    if err != nil {
        http.Error(w, err.Error(), http.StatusUnauthorized)
        return
    }
    authUID := token.UID

    // Parse conversation ID
    conversationID, err := strconv.Atoi(conversationIDStr)
    if err != nil {
        http.Error(w, "invalid conversation ID", http.StatusBadRequest)
        return
    }

	var isMember bool
    err = db.QueryRow(`
        SELECT EXISTS(
            SELECT 1 FROM conversation_members 
            WHERE conversation_id = $1 AND profile_uid = $2
        )
    `, conversationID, authUID).Scan(&isMember)
    
    if err != nil || !isMember {
        http.Error(w, "not authorized", http.StatusForbidden)
        return
    }

    // Get conversation members
    rows, err := db.Query(`
        SELECT profile_uid FROM conversation_members 
        WHERE conversation_id = $1
    `, conversationID)
    if err != nil {
        http.Error(w, "database error", http.StatusInternalServerError)
        return
    }
    defer rows.Close()

    var members []map[string]string
    for rows.Next() {
        var uid string
        if err := rows.Scan(&uid); err != nil {
            continue
        }
        members = append(members, map[string]string{"uid": uid})
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "members": members,
    })
}

func handleConversationRoutes(w http.ResponseWriter, r *http.Request) {
    path := strings.TrimPrefix(r.URL.Path, "/v1/conversations/")
    parts := strings.Split(path, "/")
    
    if len(parts) == 2 && parts[1] == "mark_read" {
        if r.Method == http.MethodPost {
            markConversationAsReadHandler(w, r)
            return
        }
    } else if len(parts) == 2 && parts[1] == "members" {
        if r.Method == http.MethodGet {
            getConversationMembersHandler(w, r, parts[0])
            return
        }
    }
    
    http.Error(w, "not found", http.StatusNotFound)
}

// getEnv reads an environment variable with a fallback default value
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func main() {
	globalHub = newHub(db)
	go globalHub.run()

	var err error
	

	// Single Firebase initialization
	if err := initFirebase(); err != nil {
        log.Fatalf("Failed to initialize Firebase: %v", err)
    }

    log.Println("Firebase Admin SDK initialized successfully.")

	// Load environment variables from .env file
	if err := godotenv.Load(); err != nil {
		log.Println("Warning: .env file not found, using environment variables")
	}

	// Build connection string from environment variables
	connStr := fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=%s timezone=%s",
		getEnv("DB_HOST", "localhost"),
		getEnv("DB_PORT", "5432"),
		getEnv("DB_USER", "postgres"),
		getEnv("DB_PASSWORD", ""),
		getEnv("DB_NAME", "zarq_messenger"),
		getEnv("DB_SSLMODE", "disable"),
		getEnv("DB_TIMEZONE", "UTC"),
	)

	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("Failed to open database connection: %v", err)
	}
	defer db.Close()

	if err = db.Ping(); err != nil {
		log.Fatalf("Failed to ping database: %v", err)
	}
	log.Printf("Successfully connected to PostgreSQL database '%s' as user '%s'",
		getEnv("DB_NAME", "zarq_messenger"),
		getEnv("DB_USER", "postgres"))

	// Database schema must be initialized using schema.sql before starting the server
	log.Println("Assuming database schema is already initialized via schema.sql")
	initGroupPermissionsSchema(db)

	initUploadsDirectory()

	// Start smart media cleanup job (runs daily at 3 AM)
	startCleanupJob(db)

	hub := globalHub

	router := mux.NewRouter()

	// REMOVED: Customization endpoints (now handled client-side with local storage)
	// - POST /v1/user/settings (UpdateUserSettingsHandler)
	// - GET /v1/user/settings (GetUserSettingsHandler)
	// - GET /v1/customization/options/bubble (GetBubbleOptionsHandler)

	router.HandleFunc("/v1/conversations/", handleConversationRoutes)

	router.HandleFunc("/v1/devices/register", basicRateLimitMiddleware(deviceRegisterHandler))
	router.HandleFunc("/v1/prekey_bundle", basicRateLimitMiddleware(getPrekeyBundleHandler))
	router.HandleFunc("/v1/turn/credentials", handlers.GetTURNCredentials).Methods("GET", "OPTIONS") // Protected endpoint for TURN credentials
	router.HandleFunc("/v1/messages/send", basicRateLimitMiddleware(sendMessageHandler))
	router.HandleFunc("/v1/messages/sync", basicRateLimitMiddleware(getMessagesHandler))
	router.HandleFunc("/v1/messages/status", basicRateLimitMiddleware(updateMessageStatusHandler))
	router.HandleFunc("/v1/users/{uid}/device", getUserDeviceHandler)
	router.HandleFunc("/v1/prekeys/count/{uid}/{deviceId}", basicRateLimitMiddleware(getPreKeyCountHandler))


	router.HandleFunc("/v1/messages/missed", basicRateLimitMiddleware(getMissedMessagesHandler))	
	router.HandleFunc("/v1/fcm/token", basicRateLimitMiddleware(updateFCMTokenHandler))
	router.HandleFunc("/v1/conversations/{id}/mark_read", markConversationAsReadHandler)
	router.HandleFunc("/v1/messages/offline", getOfflineMessagesHandler)
	router.HandleFunc("/v1/sessions", sessionStoreHandler)
	router.HandleFunc("/v1/prekeys/update", basicRateLimitMiddleware(updatePrekeysHandler))
	router.HandleFunc("/v1/files/upload", basicRateLimitMiddleware(uploadFileHandler))
	router.HandleFunc("/v1/files/{fileId}/metadata", basicRateLimitMiddleware(getAttachmentMetadataHandler))
	router.HandleFunc("/v1/files/{fileId}", basicRateLimitMiddleware(downloadFileHandler))

	router.HandleFunc("/profiles/me", getMyProfileHandler(db))
	router.HandleFunc("/profiles/check-username", RateLimitMiddleware(usernameCheckLimiter, "check-username")(checkUsernameAvailabilityHandler))
	router.HandleFunc("/profiles/create", RateLimitMiddleware(profileCreateLimiter, "create-profile")(createProfileHandler))
	router.HandleFunc("/profile/avatar/update", http.HandlerFunc(updateAvatarHandler))
	router.HandleFunc("/profile/privacy/avatar", http.HandlerFunc(updateAvatarPrivacyHandler))
	router.HandleFunc("/profile/name/update", func(w http.ResponseWriter, r *http.Request) {
		updateDisplayNameHandler(hub, w, r)
	})
	router.HandleFunc("/profile/displayname/update", http.HandlerFunc(updateUserDisplayNameHandler))

	// Delete account endpoint
	router.HandleFunc("/v1/user/account/delete", deleteAccountHandler(db)).Methods("DELETE", "OPTIONS")


	router.HandleFunc("/friends/find", http.HandlerFunc(findFriendsHandler))
	router.HandleFunc("/users/search", http.HandlerFunc(searchUsersHandler))
	router.HandleFunc("/friends/request", http.HandlerFunc(sendFriendRequestHandler))
	router.HandleFunc("/friends/requests", http.HandlerFunc(getFriendRequestsHandler))
	router.HandleFunc("/friends/accept", func(w http.ResponseWriter, r *http.Request) {
		acceptFriendRequestHandler(hub, w, r)
	})
	router.HandleFunc("/friends/decline", http.HandlerFunc(declineFriendRequestHandler))
	router.HandleFunc("/friends/remove", func(w http.ResponseWriter, r *http.Request) {
		removeFriendHandler(hub, w, r)
	})
	router.HandleFunc("/friends/list", http.HandlerFunc(getFriendsListHandler))
	router.HandleFunc("/friends/sent-requests", http.HandlerFunc(getSentFriendRequestsHandler))
	router.HandleFunc("/conversations/start", http.HandlerFunc(startOrGetConversationHandler))

	

	router.HandleFunc("/conversations/create-group", func(w http.ResponseWriter, r *http.Request) {
		createGroupHandler(hub, w, r)
	})
	router.HandleFunc("/conversations", http.HandlerFunc(getConversationsHandler))

	// Call history endpoint
	router.HandleFunc("/v1/calls/history", handlers.GetCallHistory(db))

	// Call rejection endpoint (for declining from notification)
	router.HandleFunc("/v1/calls/reject", basicRateLimitMiddleware(handleCallRejection(hub)))

	router.HandleFunc("/messages/{id:[0-9]+}", func(w http.ResponseWriter, r *http.Request) {
    if r.Method == http.MethodDelete {
        deleteMessageHandler(hub, db)(w, r)
    } else {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
    }
	}).Methods("DELETE", "OPTIONS")
	router.HandleFunc("/groups/{groupId}", func(w http.ResponseWriter, r *http.Request) {
		deleteGroupHandler(hub, w, r)
	}).Methods("DELETE", "OPTIONS")
	router.HandleFunc("/groups/{groupId}/delete", func(w http.ResponseWriter, r *http.Request) {
		deleteGroupHandler(hub, w, r)
	}).Methods("POST", "DELETE", "OPTIONS")
	router.HandleFunc("/groups/{groupId}/leave", func(w http.ResponseWriter, r *http.Request) {
		leaveGroupHandler(hub, w, r)
	}).Methods("POST")

	// Group E2EE - Sender Key Distribution Endpoints
	router.HandleFunc("/groups/{groupId}/sender-keys/distribute", distributeSenderKeyHandler).Methods("POST")
	router.HandleFunc("/groups/{groupId}/sender-keys", getGroupSenderKeysHandler).Methods("GET")

	// Key rotation endpoints (automatic only)
	router.HandleFunc("/groups/{groupId}/check-rotation", func(w http.ResponseWriter, r *http.Request) {
		checkAndRotatePeriodicHandler(hub, w, r)
	}).Methods("POST")

	// Group Info Endpoint
	router.HandleFunc("/groups/{groupId}/info", getGroupInfoHandler).Methods("GET")

	// Group Member Management Endpoints
	router.HandleFunc("/groups/{groupId}/members/add", func(w http.ResponseWriter, r *http.Request) {
		addGroupMembersHandler(hub, w, r)
	}).Methods("POST")
	router.HandleFunc("/groups/{groupId}/members/remove", func(w http.ResponseWriter, r *http.Request) {
		removeGroupMemberHandler(hub, w, r)
	}).Methods("POST")
	router.HandleFunc("/groups/{groupId}/members/role", func(w http.ResponseWriter, r *http.Request) {
		changeGroupMemberRoleHandler(hub, w, r)
	}).Methods("POST")

	// Group Info Update Endpoints
	router.HandleFunc("/groups/{groupId}/avatar", func(w http.ResponseWriter, r *http.Request) {
		updateGroupAvatarHandler(hub, w, r)
	}).Methods("POST")
	router.HandleFunc("/groups/{groupId}/update", func(w http.ResponseWriter, r *http.Request) {
		updateGroupInfoHandler(hub, w, r)
	}).Methods("POST")

	// Group Permissions & Administrative Distribution Endpoints
	router.HandleFunc("/groups/{groupId}/permissions", func(w http.ResponseWriter, r *http.Request) {
		getGroupPermissionsHandler(w, r)
	}).Methods("GET")
	router.HandleFunc("/groups/{groupId}/permissions", func(w http.ResponseWriter, r *http.Request) {
		updateGroupPermissionsHandler(hub, w, r)
	}).Methods("PUT", "POST")
	router.HandleFunc("/groups/{groupId}/join-requests", func(w http.ResponseWriter, r *http.Request) {
		getGroupJoinRequestsHandler(w, r)
	}).Methods("GET")
	router.HandleFunc("/groups/{groupId}/join-requests/{requestId}/review", func(w http.ResponseWriter, r *http.Request) {
		reviewGroupJoinRequestHandler(hub, w, r)
	}).Methods("POST")
	router.HandleFunc("/groups/{groupId}/join-requests/batch", func(w http.ResponseWriter, r *http.Request) {
		batchReviewGroupJoinRequestsHandler(hub, w, r)
	}).Methods("POST")
	router.HandleFunc("/groups/{groupId}/transfer-ownership", func(w http.ResponseWriter, r *http.Request) {
		transferGroupOwnershipHandler(hub, w, r)
	}).Methods("POST")

	router.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		serveWs(hub,db, w, r)
	})

	log.Println("Server starting on :8080")
	err = http.ListenAndServe("0.0.0.0:8080", corsMiddleware(router)) // Use the middleware here
	if err != nil {
 	    log.Fatal("ListenAndServe: ", err)
	}
}

