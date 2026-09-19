package main

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
)


type fcmTokenRequest struct {
	FCMToken  string `json:"fcm_token"`
	DeviceID  int    `json:"device_id"`
	Platform  string `json:"platform"`
}
// Request payload (matches the API spec)
type deviceRegisterRequest struct {
	FirebaseUID    string `json:"firebase_uid"`
	DeviceID       int    `json:"device_id"`
	DeviceName     string `json:"device_name"`
	Platform       string `json:"platform"`
	PushToken      string `json:"push_token"`
	IdentityKeyB64 string `json:"identity_key_b64"`
	RegistrationID int    `json:"registration_id"`

	SignedPreKey struct {
		KeyID        int    `json:"key_id"`
		PublicKeyB64 string `json:"public_key_b64"`
		SignatureB64 string `json:"signature_b64"`
	} `json:"signed_prekey"`

	OneTimePreKeys []struct {
		KeyID        int    `json:"key_id"`
		PublicKeyB64 string `json:"public_key_b64"`
	} `json:"one_time_prekeys"`
}

// Response
type deviceRegisterResponse struct {
	InsertedOneTimePrekeys int `json:"inserted_one_time_prekeys"`
	Message                string `json:"message"`
}


func updateFCMTokenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
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

	// Parse request body
	var req fcmTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	if req.DeviceID <= 0 {
    http.Error(w, "device_id is required", http.StatusBadRequest)
    return
}

	// Default platform if not provided
	if req.Platform == "" {
		req.Platform = "android"
	}

	// If FCM token is empty, clear it (for logout)
	var fcmTokenValue interface{}
	if req.FCMToken == "" {
		fcmTokenValue = nil
		log.Printf("Clearing FCM token for user %s, device %d (logout)", authUID, req.DeviceID)
	} else {
		fcmTokenValue = req.FCMToken
		log.Printf("Updating FCM token for user %s, device %d", authUID, req.DeviceID)
	}

	// Update FCM token in database
	query := `
		UPDATE devices
		SET fcm_token = $1, platform = $2, last_seen_at = $3
		WHERE firebase_uid = $4 AND device_id = $5
	`

	result, err := db.Exec(query, fcmTokenValue, req.Platform, time.Now().UTC(), authUID, req.DeviceID)
	if err != nil {
		log.Printf("updateFCMTokenHandler: database update error: %v", err)
		http.Error(w, "database error", http.StatusInternalServerError)
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		// Device doesn't exist, try to create it
		insertQuery := `
			INSERT INTO devices (firebase_uid, device_id, device_name, platform, fcm_token, last_seen_at, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			ON CONFLICT (firebase_uid, device_id) 
			DO UPDATE SET fcm_token = EXCLUDED.fcm_token, platform = EXCLUDED.platform, last_seen_at = EXCLUDED.last_seen_at
		`
		
		_, err = db.Exec(insertQuery, authUID, req.DeviceID, "Flutter Device", req.Platform, req.FCMToken, time.Now().UTC(), time.Now().UTC())
		if err != nil {
			log.Printf("updateFCMTokenHandler: device insert error: %v", err)
			http.Error(w, "database error", http.StatusInternalServerError)
			return
		}
		log.Printf("Created new device entry for %s with FCM token", authUID)
	} else {
		log.Printf("Updated FCM token for user %s, device %d", authUID, req.DeviceID)
	}

	// Success response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "FCM token updated successfully",
	})
}



// deviceRegisterHandler with Firebase auth check.
// Expects a POST with JSON body (same shape as before) but ignores any firebase_uid field
// and trusts the authenticated token's UID instead.
func deviceRegisterHandler(w http.ResponseWriter, r *http.Request) {
	// Only POST allowed
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Authenticate request (expects getVerifiedToken to be available in your codebase)
	token, _, err := getVerifiedToken(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	authUID := token.UID

	// decode JSON (we intentionally do NOT require firebase_uid from the client)
	var req struct {
		// FirebaseUID omitted/ignored: server uses authUID instead
		DeviceID       int    `json:"device_id"`
		DeviceName     string `json:"device_name"`
		Platform       string `json:"platform"`
		PushToken      string `json:"push_token"`
		IdentityKeyB64 string `json:"identity_key_b64"`
		RegistrationID int    `json:"registration_id"`

		SignedPreKey struct {
			KeyID        int    `json:"key_id"`
			PublicKeyB64 string `json:"public_key_b64"`
			SignatureB64 string `json:"signature_b64"`
		} `json:"signed_prekey"`

		OneTimePreKeys []struct {
			KeyID        int    `json:"key_id"`
			PublicKeyB64 string `json:"public_key_b64"`
		} `json:"one_time_prekeys"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	// basic validation
	if req.DeviceID <= 0 || req.IdentityKeyB64 == "" || req.RegistrationID == 0 {
		http.Error(w, "missing required fields", http.StatusBadRequest)
		return
	}

	// decode base64 fields to []byte
	identityKey, err := base64.StdEncoding.DecodeString(req.IdentityKeyB64)
	if err != nil {
		http.Error(w, "invalid base64 identity_key_b64", http.StatusBadRequest)
		return
	}
	signedPreKeyPub, err := base64.StdEncoding.DecodeString(req.SignedPreKey.PublicKeyB64)
	
	if err != nil {
		http.Error(w, "invalid base64 signed_prekey.public_key_b64", http.StatusBadRequest)
		return
	}

	hexPreview := fmt.Sprintf("%x", signedPreKeyPub)
	first := byte(0)
	if len(signedPreKeyPub) > 0 { first = signedPreKeyPub[0] }
	log.Printf("SignedPreKey: decoded %d bytes; first=0x%02x; hex-prefix=%s", len(signedPreKeyPub), first, hexPreview[:min(len(hexPreview), 80)])

	signedPreKeySig, err := base64.StdEncoding.DecodeString(req.SignedPreKey.SignatureB64)
	if err != nil {
		http.Error(w, "invalid base64 signed_prekey.signature_b64", http.StatusBadRequest)
		return
	}

	// Begin transaction
	tx, err := db.Begin()
	if err != nil {
		log.Printf("deviceRegisterHandler: begin tx error: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer func() {
		_ = tx.Rollback()
	}()

	now := time.Now().UTC()

	// Ensure profile exists for authUID (fail if not)
	var exists bool
	err = tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM profiles WHERE firebase_uid = $1)`, authUID).Scan(&exists)
	if err != nil {
		log.Printf("deviceRegisterHandler: check profile exists error: %v", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	if !exists {
		http.Error(w, "profile not found; create profile first", http.StatusBadRequest)
		return
	}

	// Check if this user already has a device registered (device replacement detection)
var existingDeviceId sql.NullInt64
err = tx.QueryRow(`
	SELECT device_id FROM devices 
	WHERE firebase_uid = $1 
	ORDER BY last_seen_at DESC 
	LIMIT 1
`, authUID).Scan(&existingDeviceId)

if err == nil && existingDeviceId.Valid {
	if int(existingDeviceId.Int64) != req.DeviceID {
		// Same user re-registering with different device ID - replace the old device
		log.Printf("User %s re-registering: replacing device %d with %d", 
			authUID, existingDeviceId.Int64, req.DeviceID)
		
		// Delete old device and related keys
		_, err = tx.Exec(`DELETE FROM devices WHERE firebase_uid = $1`, authUID)
		if err != nil {
			log.Printf("deviceRegisterHandler: delete existing devices error: %v", err)
			http.Error(w, "db error", http.StatusInternalServerError)
			return
		}
		
		_, err = tx.Exec(`DELETE FROM identity_keys WHERE firebase_uid = $1`, authUID)
		if err != nil {
			log.Printf("deviceRegisterHandler: delete existing identity_keys error: %v", err)
			http.Error(w, "db error", http.StatusInternalServerError)
			return
		}
		
		_, err = tx.Exec(`DELETE FROM signed_pre_keys WHERE firebase_uid = $1`, authUID)
		if err != nil {
			log.Printf("deviceRegisterHandler: delete existing signed_pre_keys error: %v", err)
			http.Error(w, "db error", http.StatusInternalServerError)
			return
		}
		
		_, err = tx.Exec(`DELETE FROM one_time_pre_keys WHERE firebase_uid = $1`, authUID)
		if err != nil {
			log.Printf("deviceRegisterHandler: delete existing one_time_pre_keys error: %v", err)
			http.Error(w, "db error", http.StatusInternalServerError)
			return
		}
	} else {
		log.Printf("User %s updating existing device %d", authUID, req.DeviceID)
	}
} else if err != sql.ErrNoRows {
	log.Printf("deviceRegisterHandler: check existing device error: %v", err)
	http.Error(w, "db error", http.StatusInternalServerError)
	return
}

	// 1) Upsert device row
	_, err = tx.Exec(`
		INSERT INTO devices (firebase_uid, device_id, device_name, platform, push_token, last_seen_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (firebase_uid, device_id) DO UPDATE
		  SET device_name = EXCLUDED.device_name,
		      platform = EXCLUDED.platform,
		      push_token = EXCLUDED.push_token,
		      last_seen_at = EXCLUDED.last_seen_at
	`, authUID, req.DeviceID, req.DeviceName, req.Platform, req.PushToken, now, now)
	if err != nil {
		log.Printf("deviceRegisterHandler: upsert devices error: %v", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}

	// 2) Upsert identity_keys
	_, err = tx.Exec(`
		INSERT INTO identity_keys (firebase_uid, device_id, public_key, registration_id, created_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (firebase_uid, device_id) DO UPDATE
		  SET public_key = EXCLUDED.public_key,
		      registration_id = EXCLUDED.registration_id,
		      created_at = EXCLUDED.created_at
	`, authUID, req.DeviceID, identityKey, req.RegistrationID, now)
	if err != nil {
		log.Printf("deviceRegisterHandler: upsert identity_keys error: %v", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}

	// 3) Upsert signed_pre_keys
	_, err = tx.Exec(`
		INSERT INTO signed_pre_keys (key_id, firebase_uid, device_id, public_key, signature, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (firebase_uid, device_id, key_id) DO UPDATE
		  SET public_key = EXCLUDED.public_key,
		      signature = EXCLUDED.signature,
		      created_at = EXCLUDED.created_at
	`, req.SignedPreKey.KeyID, authUID, req.DeviceID, signedPreKeyPub, signedPreKeySig, now)
	if err != nil {
		log.Printf("deviceRegisterHandler: upsert signed_pre_keys error: %v", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}

	// 4) Bulk insert one_time_pre_keys (ON CONFLICT DO NOTHING)
	insertedCount := 0
	if len(req.OneTimePreKeys) > 0 {
		stmt, err := tx.Prepare(`
			INSERT INTO one_time_pre_keys (key_id, firebase_uid, device_id, public_key, consumed, created_at)
			VALUES ($1, $2, $3, $4, false, $5)
			ON CONFLICT (firebase_uid, device_id, key_id) DO NOTHING
		`)
		if err != nil {
			log.Printf("deviceRegisterHandler: prepare one_time_pre_keys insert error: %v", err)
			http.Error(w, "db error", http.StatusInternalServerError)
			return
		}
		defer stmt.Close()

		for _, otp := range req.OneTimePreKeys {
			if otp.KeyID <= 0 {
				continue
			}
			pub, err := base64.StdEncoding.DecodeString(otp.PublicKeyB64)
			if err != nil {
				// skip invalid key (don't abort whole batch)
				log.Printf("deviceRegisterHandler: skipping invalid one-time prekey base64: %v", err)
				continue
			}
			res, err := stmt.Exec(otp.KeyID, authUID, req.DeviceID, pub, now)
			if err != nil {
				log.Printf("deviceRegisterHandler: insert one_time_pre_key exec error: %v", err)
				continue
			}
			ra, _ := res.RowsAffected()
			if ra > 0 {
				insertedCount++
			}
		}
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		log.Printf("deviceRegisterHandler: commit error: %v", err)
		http.Error(w, "db commit error", http.StatusInternalServerError)
		return
	}

	// Success response
	resp := struct {
		InsertedOneTimePrekeys int    `json:"inserted_one_time_prekeys"`
		Message                string `json:"message"`
	}{
		InsertedOneTimePrekeys: insertedCount,
		Message:                "device registered",
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}


func getPrekeyBundleHandler(w http.ResponseWriter, r *http.Request) {
	// Only GET allowed
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Auth
	token, _, err := getVerifiedToken(r)
    if err != nil {
//         log.Printf("DEBUG: Auth failed with current serviceAccountKey: %v", err)
        http.Error(w, err.Error(), http.StatusUnauthorized)
        return
    }

	_ = token // we don't need the caller UID, but require auth

	// Read query params
	targetUID := r.URL.Query().Get("uid")
	deviceIDStr := r.URL.Query().Get("device_id")
	if targetUID == "" || deviceIDStr == "" {
		http.Error(w, "missing uid or device_id query parameter", http.StatusBadRequest)
		return
	}
	deviceID, err := strconv.Atoi(deviceIDStr)
	if err != nil || deviceID <= 0 {
		http.Error(w, "invalid device_id", http.StatusBadRequest)
		return
	}

	// 1) Attempt to consume one-time prekey (returns 0 or 1 row)
	var consumedUID string
	var consumedDevice int
	var consumedKeyID int
	var consumedPubB64 sql.NullString

	err = db.QueryRow(`
		SELECT firebase_uid, device_id, key_id, public_key_b64
		FROM consume_one_time_prekey($1, $2)
	`, targetUID, deviceID).Scan(&consumedUID, &consumedDevice, &consumedKeyID, &consumedPubB64)
	// Note: consume_one_time_prekey returns zero rows if none available.
	consumedAvailable := true
	if err == sql.ErrNoRows {
		consumedAvailable = false
	} else if err != nil {
		log.Printf("getPrekeyBundleHandler: consume_one_time_prekey error: %v", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}

	// 2) Fetch the current bundle from the view (this reflects remaining one_time_prekeys_available)
	var identityKeyB64 sql.NullString
	var registrationID sql.NullInt64
	var signedPrekeyID sql.NullInt64
	var signedPrekeyB64 sql.NullString
	var signedPrekeySigB64 sql.NullString
	var otpAvailable sql.NullInt64
	var bundleCreatedAt sql.NullTime

	err = db.QueryRow(`
		SELECT identity_key_b64, registration_id, signed_prekey_id, signed_prekey_b64, signed_prekey_signature_b64, one_time_prekeys_available, bundle_created_at
		FROM prekey_bundles
		WHERE firebase_uid = $1 AND device_id = $2
	`, targetUID, deviceID).Scan(&identityKeyB64, &registrationID, &signedPrekeyID, &signedPrekeyB64, &signedPrekeySigB64, &otpAvailable, &bundleCreatedAt)

	if err == sql.ErrNoRows {
		http.Error(w, "prekey bundle not found", http.StatusNotFound)
		return
	} else if err != nil {
		log.Printf("getPrekeyBundleHandler: prekey_bundles query error: %v", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}

	// Build JSON response
	type signedPrekeyResp struct {
		KeyID         *int   `json:"key_id,omitempty"`
		PublicKeyB64  string `json:"public_key_b64,omitempty"`
		SignatureB64  string `json:"signature_b64,omitempty"`
	}
	resp := map[string]interface{}{}
	resp["firebase_uid"] = targetUID
	resp["device_id"] = deviceID
	if identityKeyB64.Valid {
		resp["identity_key_b64"] = identityKeyB64.String
	} else {
		resp["identity_key_b64"] = nil
	}
	if registrationID.Valid {
		resp["registration_id"] = registrationID.Int64
	} else {
		resp["registration_id"] = nil
	}
	// signed prekey object
	if signedPrekeyID.Valid {
    	resp["signed_prekey_id"] = signedPrekeyID.Int64
	} else {
    	resp["signed_prekey_id"] = nil
	}

	if signedPrekeyB64.Valid {
    	resp["signed_prekey_b64"] = signedPrekeyB64.String
	} else {
    	resp["signed_prekey_b64"] = nil
	}

	if signedPrekeySigB64.Valid {
    	resp["signed_prekey_signature_b64"] = signedPrekeySigB64.String
	} else {
    	resp["signed_prekey_signature_b64"] = nil
	}

// FIXED: Include consumed one-time prekey with ID
	if consumedAvailable && consumedPubB64.Valid {
    	resp["one_time_prekey_id"] = consumedKeyID
    	resp["one_time_prekey_b64"] = consumedPubB64.String
	} else {
    	resp["one_time_prekey_id"] = nil
    	resp["one_time_prekey_b64"] = nil
	}

	// remaining count
	if otpAvailable.Valid {
    	resp["one_time_prekeys_available"] = otpAvailable.Int64
	} else {
    	resp["one_time_prekeys_available"] = 0
	}

	// Return JSON
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func sendMessageHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Auth
	token, _, err := getVerifiedToken(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	senderUID := token.UID

	// Decode body
	var req struct {
		ConversationID     int     `json:"conversation_id"`
		ContentB64         string  `json:"content_b64"`
		MessageType        string  `json:"message_type"`
		EphemeralExpiresAt *string `json:"ephemeral_expires_at"`
		SessionContextB64  string  `json:"session_context_b64"` 
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if req.ConversationID <= 0 || req.ContentB64 == "" {
		http.Error(w, "missing required fields", http.StatusBadRequest)
		return
	}

	// Decode content
	contentBytes, err := base64.StdEncoding.DecodeString(req.ContentB64)
	if err != nil {
		http.Error(w, "invalid base64 content", http.StatusBadRequest)
		return
	}

	// SECURITY: Validate that content is encrypted Signal Protocol ciphertext
	if len(contentBytes) < 1 {
		log.Printf("sendMessageHandler: SECURITY - Empty content rejected from %s", senderUID)
		http.Error(w, "encrypted content required", http.StatusBadRequest)
		return
	}

	// Signal Protocol messages start with version byte (0x33 for v3, 0x03 for older)
	versionByte := contentBytes[0]
	if versionByte != 0x33 && versionByte != 0x03 {
		log.Printf("sendMessageHandler: SECURITY - Content does not appear to be Signal Protocol encrypted (version byte: 0x%02x) from %s", versionByte, senderUID)
		http.Error(w, "content must be Signal Protocol encrypted", http.StatusBadRequest)
		return
	}

	log.Printf("sendMessageHandler: ✅ Validated Signal Protocol encrypted content from %s (version: 0x%02x)", senderUID, versionByte)

	// Start transaction
	tx, err := db.Begin()
	if err != nil {
		log.Printf("sendMessageHandler: begin tx error: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	// 1) Verify sender is a member of conversation
	var isMember bool
	err = tx.QueryRow(`
		SELECT EXISTS(
		  SELECT 1 FROM conversation_members WHERE conversation_id = $1 AND profile_uid = $2
		)
	`, req.ConversationID, senderUID).Scan(&isMember)
	if err != nil {
		log.Printf("sendMessageHandler: check membership error: %v", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	if !isMember {
		http.Error(w, "not a member of conversation", http.StatusForbidden)
		return
	}
	// 2) Insert message
	var senderDeviceID int
	err = db.QueryRow("SELECT device_id FROM devices WHERE firebase_uid = $1 LIMIT 1", senderUID).Scan(&senderDeviceID)
	if err != nil {
    	log.Printf("sendMessageHandler: Could not get sender device ID for %s: %v", senderUID, err)
    	senderDeviceID = 1 // fallback only if lookup fails
	}

	var messageID int
	query := `
    	INSERT INTO messages (conversation_id, sender_uid, sender_device_id, content, message_type, ephemeral_expires_at, created_at)
    	VALUES ($1, $2, $3, $4, $5, $6, NOW() AT TIME ZONE 'UTC')
    	RETURNING id
	`
	err = tx.QueryRow(query, req.ConversationID, senderUID, senderDeviceID, contentBytes, coalesceString(req.MessageType, "chat"), req.EphemeralExpiresAt).Scan(&messageID)
	if err != nil {
		log.Printf("sendMessageHandler: insert message error: %v", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	//log.Printf("DEBUG: Message inserted with ID: %d", messageID)

	// 3) Get recipient devices and check online status
	rows, err := tx.Query(`
		SELECT cm.profile_uid, d.device_id, d.push_token
		FROM conversation_members cm
		JOIN devices d ON d.firebase_uid = cm.profile_uid
		WHERE cm.conversation_id = $1 AND cm.profile_uid != $2
	`, req.ConversationID, senderUID)
	if err != nil {
		log.Printf("sendMessageHandler: select recipient devices error: %v", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type recipientInfo struct {
		UID       string
		DeviceID  int
		PushToken sql.NullString
		IsOnline  bool
	}
	var recipients []recipientInfo

	for rows.Next() {
		var recipient string
		var deviceID int
		var pushToken sql.NullString
		if err := rows.Scan(&recipient, &deviceID, &pushToken); err != nil {
			log.Printf("sendMessageHandler: row scan error: %v", err)
			continue
		}

		// Check if recipient is online (connected to WebSocket)
		isOnline := isUserOnline(recipient)
		log.Printf("Recipient %s online status: %v", recipient, isOnline)

		recipients = append(recipients, recipientInfo{
			UID:       recipient,
			DeviceID:  deviceID,
			PushToken: pushToken,
			IsOnline:  isOnline,
		})
	}

	if err := rows.Err(); err != nil {
		log.Printf("sendMessageHandler: rows err: %v", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}

	// 4) Process each recipient with detailed logging
	//log.Printf("DEBUG: Processing %d recipients", len(recipients))
	
	for _, r := range recipients {
		//log.Printf("DEBUG: Processing recipient %s, online: %v", r.UID, r.IsOnline)
		
		// Insert message_status
		//log.Printf("DEBUG: Inserting message_status for recipient %s", r.UID)
		_, err = tx.Exec(`
			INSERT INTO message_status (message_id, recipient_uid, recipient_device_id, delivered_at)
			VALUES ($1, $2, $3, NULL)
			ON CONFLICT (message_id, recipient_uid, recipient_device_id) DO NOTHING
		`, messageID, r.UID, r.DeviceID)
		if err != nil {
			log.Printf("ERROR: message_status insert failed for %s: %v", r.UID, err)
		} else {
			//log.Printf("DEBUG: message_status inserted successfully for %s", r.UID)
		}

		// Queue message for offline users
		// In the recipient processing loop, update the offline queueing
if !r.IsOnline {
    // Decode session context
    var sessionContextBytes []byte
    if req.SessionContextB64 != "" {
        var err error
        sessionContextBytes, err = base64.StdEncoding.DecodeString(req.SessionContextB64)
        if err != nil {
            log.Printf("ERROR: Invalid session context base64: %v", err)
            sessionContextBytes = nil
        }
    }
    
    //log.Printf("DEBUG: Queueing offline message with session context for %s", r.UID)
    _, err = tx.Exec(`
        INSERT INTO offline_message_queue (recipient_uid, sender_uid, conversation_id, message_id, encrypted_content, session_context, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, NOW() AT TIME ZONE 'UTC')
    `, r.UID, senderUID, req.ConversationID, messageID, contentBytes, sessionContextBytes)
    
	var senderDisplayName string
	err = db.QueryRow(`SELECT username FROM profiles WHERE firebase_uid = $1`, senderUID).Scan(&senderDisplayName)

    if err != nil {
        log.Printf("ERROR: offline queue insert failed for %s: %v", r.UID, err)
    } else {
        //log.Printf("DEBUG: offline message with session context queued successfully for %s", r.UID)

		messageData := map[string]interface{}{
        "type":            "new_message",
        "message_id":      messageID,
        "conversation_id": req.ConversationID,
        "sender_uid":      senderUID,
        "sender_username": senderDisplayName,
        "content_b64":     req.ContentB64, // Encrypted content
    }
    sendNewMessageNotificationFromMessage(r.UID, messageData)
    }
}
	}

// log.Printf("DEBUG: Checking if sender %s is online...", senderUID)
isSenderOnline := isUserOnline(senderUID)
// log.Printf("DEBUG: Sender %s online status: %v", senderUID, isSenderOnline)

if !isSenderOnline {
//     log.Printf("DEBUG: Sender %s is offline, queueing message for sender to see when they reconnect", senderUID)

    // Queue the message for the sender too, so they see it when they open the app
    _, err = tx.Exec(`
        INSERT INTO offline_message_queue (recipient_uid, sender_uid, conversation_id, message_id, encrypted_content, session_context, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, NOW() AT TIME ZONE 'UTC')
    `, senderUID, senderUID, req.ConversationID, messageID, contentBytes, nil)

    if err != nil {
        log.Printf("ERROR: Failed to queue message for sender %s: %v", senderUID, err)
    } else {
//         log.Printf("DEBUG: Successfully queued message for sender %s", senderUID)
    }
} else {
//     log.Printf("DEBUG: Sender %s is ONLINE, NOT queueing message for sender", senderUID)
}

	// Commit transaction
	//log.Printf("DEBUG: Committing transaction...")
	if err := tx.Commit(); err != nil {
		log.Printf("sendMessageHandler: commit error: %v", err)
		http.Error(w, "db commit error", http.StatusInternalServerError)
		return
	}
	//log.Printf("DEBUG: Transaction committed successfully")

	// 6) Broadcast to online users via WebSocket
	go func(convID int, msgID int, senderUID string, contentB64 string, recipients []recipientInfo) {
    // Get sender's display name
    var senderDisplayName string
    err := db.QueryRow(`SELECT username FROM profiles WHERE firebase_uid = $1`, senderUID).Scan(&senderDisplayName)
    if err != nil {
        senderDisplayName = "Unknown User"
        log.Printf("Could not fetch sender display name: %v", err)
    }
    
    var storedTimestamp time.Time
    err = db.QueryRow(`SELECT created_at FROM messages WHERE id = $1`, msgID).Scan(&storedTimestamp)
    if err != nil {
        storedTimestamp = time.Now().UTC()
    }

    // Query if conversation is a group
    var isGroup bool
    err = db.QueryRow(`SELECT is_group FROM conversations WHERE id = $1`, convID).Scan(&isGroup)
    if err != nil {
        log.Printf("Failed to query is_group for conversation %d: %v", convID, err)
        isGroup = false
    }
//     log.Printf("DEBUG: Conversation %d, is_group: %v", convID, isGroup)

    // Create WebSocket message payload
    wsMessage := map[string]interface{}{
        "type":             "new_message",
        "message_id":       msgID,
        "conversation_id":  convID,
        "sender_uid":       senderUID,
        "sender_username":  senderDisplayName,
        "sender_device_id": senderDeviceID,
        "content_b64":      contentB64,
        "created_at":       storedTimestamp.UTC().Format(time.RFC3339),
        "is_group":         isGroup,
    }
//     log.Printf("DEBUG: wsMessage created with is_group: %v", wsMessage["is_group"])

//     log.Printf("DEBUG: About to broadcast message to recipients, wsMessage[is_group]=%v", wsMessage["is_group"])

    // Only broadcast to online recipients
    onlineCount := 0
    for _, r := range recipients {
        if r.IsOnline {
//             log.Printf("DEBUG: Broadcasting to online user %s, is_group=%v", r.UID, wsMessage["is_group"])
            broadcastToUser(globalHub, r.UID, wsMessage)
            onlineCount++
        }
    }

    log.Printf("Broadcasted message %d to %d online recipients", msgID, onlineCount)
	}(req.ConversationID, messageID, senderUID, req.ContentB64, recipients)

	// 7) Send push notifications to offline users
	go func(recipients []recipientInfo, mid int) {
		for _, r := range recipients {
			if !r.IsOnline && r.PushToken.Valid && r.PushToken.String != "" {
				// Send push notification to offline user
				// call your FCM sender here with r.PushToken.String
				log.Printf("Sending push notification to offline user %s", r.UID)
			}
		}
	}(recipients, messageID)

	// Success response
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"message_id": messageID,
		"status":     "ok",
	})
}

func getOfflineMessagesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Auth
	token, _, err := getVerifiedToken(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	userUID := token.UID

	// Start transaction for atomic operations
	tx, err := db.Begin()
	if err != nil {
		log.Printf("getOfflineMessagesHandler: begin tx error: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	// Get all undelivered messages for this user
	rows, err := tx.Query(`
    SELECT omq.message_id, omq.sender_uid, omq.conversation_id, omq.encrypted_content, omq.session_context, omq.created_at,
           p.username as sender_username, omq.id as queue_id, c.is_group
    FROM offline_message_queue omq
    JOIN profiles p ON p.firebase_uid = omq.sender_uid
    JOIN conversations c ON c.id = omq.conversation_id
    WHERE omq.recipient_uid = $1 AND omq.delivered = false
    ORDER BY omq.created_at ASC
`, userUID)


	if err != nil {
		log.Printf("getOfflineMessagesHandler: query error: %v", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var messages []map[string]interface{}
	var queueIDs []int

	for rows.Next() {
		var messageID int
		var senderUID string
		var conversationID int
		var encryptedContent []byte
		var createdAt time.Time
		var senderUsername string
		var queueID int
		var sessionContext []byte
		var isGroup bool

		err := rows.Scan(&messageID, &senderUID, &conversationID, &encryptedContent, &sessionContext, &createdAt, &senderUsername, &queueID, &isGroup)

		if err != nil {
			log.Printf("getOfflineMessagesHandler: scan error: %v", err)
			continue
		}

		// Convert encrypted content to base64 for client
		contentB64 := base64.StdEncoding.EncodeToString(encryptedContent)

		message := map[string]interface{}{
			"message_id":      messageID,
			"sender_uid":      senderUID,
			"sender_username": senderUsername,
			"conversation_id": conversationID,
			"content_b64":     contentB64,
			"session_context_b64": "",
			"created_at":      createdAt.UTC().Format(time.RFC3339),
			"sender_device_id": 1, // Default device ID
			"is_group":        isGroup,
		}

		if sessionContext != nil {
    		message["session_context_b64"] = base64.StdEncoding.EncodeToString(sessionContext)
		}

		messages = append(messages, message)
		queueIDs = append(queueIDs, queueID)
	}

	if err := rows.Err(); err != nil {
		log.Printf("getOfflineMessagesHandler: rows error: %v", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}

	// Mark messages as delivered
	if len(queueIDs) > 0 {
		// Build placeholders for IN clause
		placeholders := make([]string, len(queueIDs))
		args := make([]interface{}, len(queueIDs))
		for i, id := range queueIDs {
			placeholders[i] = "$" + strconv.Itoa(i+1)
			args[i] = id
		}

		updateQuery := `
			UPDATE offline_message_queue 
			SET delivered = true, delivered_at = NOW() 
			WHERE id IN (` + strings.Join(placeholders, ",") + `)`

		_, err = tx.Exec(updateQuery, args...)
		if err != nil {
			log.Printf("getOfflineMessagesHandler: update delivered error: %v", err)
			http.Error(w, "db error", http.StatusInternalServerError)
			return
		}

		log.Printf("Marked %d offline messages as delivered for user %s", len(queueIDs), userUID)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		log.Printf("getOfflineMessagesHandler: commit error: %v", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}

	// Return response
	response := map[string]interface{}{
		"messages": messages,
		"count":    len(messages),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
// Helper function to check if user is online (connected to WebSocket)
func isUserOnline(userUID string) bool {
    _, exists := globalHub.clients[userUID]
    
    // Debug logging to verify
    //log.Printf("DEBUG: isUserOnline(%s) = %v (total clients: %d)", userUID, exists, len(globalHub.clients))
    
    return exists
}

// helper to use default string if empty
func coalesceString(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func getMessagesHandler(w http.ResponseWriter, r *http.Request) {
	// Only GET allowed
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Auth
	token, _, err := getVerifiedToken(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	authUID := token.UID

	// Parse query params
	q := r.URL.Query()
	convIDStr := q.Get("conversation_id")
	if convIDStr == "" {
		http.Error(w, "conversation_id required", http.StatusBadRequest)
		return
	}
	convID, err := strconv.Atoi(convIDStr)
	if err != nil || convID <= 0 {
		http.Error(w, "invalid conversation_id", http.StatusBadRequest)
		return
	}

	sinceID := 0
	if s := q.Get("since_id"); s != "" {
		if v, err := strconv.Atoi(s); err == nil && v >= 0 {
			sinceID = v
		}
	}

	limit := 100
	if l := q.Get("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 && v <= 1000 {
			limit = v
		}
	}

	// Start a transaction (read-only)
	tx, err := db.Begin()
	if err != nil {
		log.Printf("getMessagesHandler: begin tx error: %v", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	// Verify caller is a member of the conversation
	var isMember bool
	err = tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM conversation_members WHERE conversation_id = $1 AND profile_uid = $2)`, convID, authUID).Scan(&isMember)
	if err != nil {
		log.Printf("getMessagesHandler: membership check error: %v", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	if !isMember {
		http.Error(w, "not a member of conversation", http.StatusForbidden)
		return
	}

	// Fetch messages with username lookup (JOIN with profiles table)
	msgRows, err := tx.Query(`
		SELECT m.id, m.conversation_id, m.sender_uid, p.display_name, m.sender_device_id, m.content, m.created_at, COALESCE(m.message_type, 'chat') as message_type
		FROM messages m
		JOIN profiles p ON p.firebase_uid = m.sender_uid
		WHERE m.conversation_id = $1 AND m.id > $2
		ORDER BY m.id ASC
		LIMIT $3
	`, convID, sinceID, limit)
	if err != nil {
		log.Printf("getMessagesHandler: query messages error: %v", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	defer msgRows.Close()

	type statusResp struct {
		RecipientDeviceID int        `json:"recipient_device_id"`
		DeliveredAt       *time.Time `json:"delivered_at,omitempty"`
		ReadAt            *time.Time `json:"read_at,omitempty"`
	}
	type msgResp struct {
		ID            int          `json:"id"`
		Conversation  int          `json:"conversation_id"`
		SenderUID     string       `json:"sender_uid"`
		Username      string       `json:"username"`
		SenderDevice  int          `json:"sender_device_id"`
		ContentB64    string       `json:"content_b64"`
		CreatedAt     time.Time    `json:"created_at"`
		MessageType   string       `json:"message_type"`
		Statuses      []statusResp `json:"statuses"`
	}

	var results []msgResp

	for msgRows.Next() {
		var id int
		var conversationID int
		var senderUID string
		var username string  // Added username variable
		var senderDeviceID int
		var contentBytes []byte
		var createdAt time.Time
		var messageType string

		// Updated scan to include username and message_type
		if err := msgRows.Scan(&id, &conversationID, &senderUID, &username, &senderDeviceID, &contentBytes, &createdAt, &messageType); err != nil {
			log.Printf("getMessagesHandler: scan msg row error: %v", err)
			continue
		}

		// Base64 encode ciphertext
		contentB64 := base64.StdEncoding.EncodeToString(contentBytes)

		// Fetch statuses for this message where recipient = authUID (all devices)
		statusRows, err := tx.Query(`
			SELECT recipient_device_id, delivered_at, read_at
			FROM message_status
			WHERE message_id = $1 AND recipient_uid = $2
			ORDER BY recipient_device_id
		`, id, authUID)
		if err != nil {
			log.Printf("getMessagesHandler: query message_status error for msg %d: %v", id, err)
			// continue with empty statuses rather than aborting whole request
			results = append(results, msgResp{
				ID:           id,
				Conversation: conversationID,
				SenderUID:    senderUID,
				Username:     username,  // Include username in error case
				SenderDevice: senderDeviceID,
				ContentB64:   contentB64,
				CreatedAt:    createdAt,
				MessageType:  messageType,
				Statuses:     nil,
			})
			continue
		}

		var statuses []statusResp
		for statusRows.Next() {
			var recipientDeviceID int
			var deliveredAt sql.NullTime
			var readAt sql.NullTime
			if err := statusRows.Scan(&recipientDeviceID, &deliveredAt, &readAt); err != nil {
				log.Printf("getMessagesHandler: scan status row error: %v", err)
				continue
			}
			var da *time.Time
			var ra *time.Time
			if deliveredAt.Valid {
				t := deliveredAt.Time
				da = &t
			}
			if readAt.Valid {
				t := readAt.Time
				ra = &t
			}
			statuses = append(statuses, statusResp{
				RecipientDeviceID: recipientDeviceID,
				DeliveredAt:       da,
				ReadAt:            ra,
			})
		}
		statusRows.Close()

		// Include username in the final result
		results = append(results, msgResp{
			ID:           id,
			Conversation: conversationID,
			SenderUID:    senderUID,
			Username:     username,  // Include username
			SenderDevice: senderDeviceID,
			ContentB64:   contentB64,
			CreatedAt:    createdAt,
			MessageType:  messageType,
			Statuses:     statuses,
		})
	}
	if err := msgRows.Err(); err != nil {
		log.Printf("getMessagesHandler: msgRows err: %v", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}

	// Commit read-only transaction (commit to release any locks)
	if err := tx.Commit(); err != nil {
		log.Printf("getMessagesHandler: commit error: %v", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}

	// Return JSON
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"messages": results,
	})
}



func updateMessageStatusHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Authenticate caller
	token, _, err := getVerifiedToken(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	authUID := token.UID

	// Parse request body
	var req struct {
		MessageID         int     `json:"message_id"`
		RecipientDeviceID *int    `json:"recipient_device_id,omitempty"`
		Delivered         *bool   `json:"delivered,omitempty"`
		Read              *bool   `json:"read,omitempty"`
		DeliveredAtStr    *string `json:"delivered_at,omitempty"`
		ReadAtStr         *string `json:"read_at,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if req.MessageID <= 0 {
		http.Error(w, "message_id required", http.StatusBadRequest)
		return
	}

	// Determine timestamps to set
	var deliveredAt *time.Time
	var readAt *time.Time
	now := time.Now().UTC()

	if req.Delivered != nil && *req.Delivered {
		t := now
		deliveredAt = &t
	}
	if req.Read != nil && *req.Read {
		t := now
		readAt = &t
	}
	// If explicit timestamps provided, parse them (they override booleans)
	if req.DeliveredAtStr != nil && *req.DeliveredAtStr != "" {
		if t, err := time.Parse(time.RFC3339, *req.DeliveredAtStr); err == nil {
			deliveredAt = &t
		} else {
			http.Error(w, "invalid delivered_at format (use RFC3339)", http.StatusBadRequest)
			return
		}
	}
	if req.ReadAtStr != nil && *req.ReadAtStr != "" {
		if t, err := time.Parse(time.RFC3339, *req.ReadAtStr); err == nil {
			readAt = &t
		} else {
			http.Error(w, "invalid read_at format (use RFC3339)", http.StatusBadRequest)
			return
		}
	}

	// Build UPDATE SQL dynamically depending on fields
	setClauses := []string{}
	args := []interface{}{}
	argPos := 1

	if deliveredAt != nil {
		setClauses = append(setClauses, "delivered_at = $"+strconv.Itoa(argPos))
		args = append(args, *deliveredAt)
		argPos++
	}
	if readAt != nil {
		setClauses = append(setClauses, "read_at = $"+strconv.Itoa(argPos))
		args = append(args, *readAt)
		argPos++
	}

	if len(setClauses) == 0 {
		http.Error(w, "nothing to update (provide delivered/read or timestamps)", http.StatusBadRequest)
		return
	}

	// WHERE clause: message_id AND recipient_uid = authUID, optionally recipient_device_id
	whereClause := " WHERE message_id = $" + strconv.Itoa(argPos) + " AND recipient_uid = $" + strconv.Itoa(argPos+1)
	args = append(args, req.MessageID, authUID)
	argPos += 2

	if req.RecipientDeviceID != nil {
		whereClause += " AND recipient_device_id = $" + strconv.Itoa(argPos)
		args = append(args, *req.RecipientDeviceID)
		argPos++
	}

	// Assemble final SQL
	sqlStmt := "UPDATE message_status SET " + strings.Join(setClauses, ", ") + whereClause

	// Execute and report rows updated
	res, err := db.Exec(sqlStmt, args...)
	if err != nil {
		log.Printf("updateMessageStatusHandler: exec error: %v", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	ra, _ := res.RowsAffected()

	// Return response
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"updated": ra,
		"message": "ok",
	})
}

func getMissedMessagesHandler(w http.ResponseWriter, r *http.Request) {
    // Get user from JWT token
    uid := getUserUIDFromToken(r)
    if uid == "" {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }

    // Get query parameter for last sync timestamp
    lastSync := r.URL.Query().Get("since")
    if lastSync == "" {
        http.Error(w, "Missing 'since' parameter", http.StatusBadRequest)
        return
    }

	var sinceTime time.Time
    var err error
    // Parse timestamp
    sinceTime, err = time.Parse(time.RFC3339Nano, lastSync)
    if err != nil {
        // Fallback to standard RFC3339 (without microseconds)
        sinceTime, err = time.Parse(time.RFC3339, lastSync)
        if err != nil {
            log.Printf("Invalid timestamp format: %s, error: %v", lastSync, err)
            http.Error(w, "Invalid timestamp format", http.StatusBadRequest)
            return
        }
    }

	log.Printf("Parsed timestamp successfully: %v", sinceTime)

    // Query messages for user's conversations since the timestamp
    query := `
    SELECT m.id, m.conversation_id, m.sender_uid, m.content, m.created_at, p.username
    FROM messages m
    JOIN conversation_members cm ON m.conversation_id = cm.conversation_id
    JOIN profiles p ON m.sender_uid = p.firebase_uid
    WHERE cm.profile_uid = $1 
    AND m.created_at > $2
    ORDER BY m.created_at ASC
`

    rows, err := db.Query(query, uid, sinceTime)
    if err != nil {
        log.Printf("Error fetching missed messages: %v", err)
        http.Error(w, "Database error", http.StatusInternalServerError)
        return
    }
    defer rows.Close()

    var messages []map[string]interface{}
    for rows.Next() {
        var msg Message
        var username string
        var contentBytes []byte
err :=  rows.Scan(&msg.ID, &msg.ConversationID, &msg.SenderUID, &contentBytes, &msg.Timestamp, &username)
        if err != nil {
            continue
        }

        messages = append(messages, map[string]interface{}{
    "message_id":      msg.ID,
    "conversation_id": msg.ConversationID,
    "sender_uid":      msg.SenderUID,
    "sender_username": username,
    "content_b64":     base64.StdEncoding.EncodeToString(contentBytes),
    "created_at":      msg.Timestamp.UTC().Format(time.RFC3339),
    "sender_device_id": 1,
})
	}

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "messages": messages,
    })
}

func getUserUIDFromToken(r *http.Request) string {
    authHeader := r.Header.Get("Authorization")
    if authHeader == "" {
        return ""
    }
    
    tokenString := strings.TrimPrefix(authHeader, "Bearer ")
    if tokenString == authHeader {
        return ""
    }
    
    token, err := firebaseAuth.VerifyIDToken(context.Background(), tokenString)
    if err != nil {
        log.Printf("Token verification failed: %v", err)
        return ""
    }
    
    return token.UID
}

func markConversationAsReadHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("markConversationAsReadHandler called - Method: %s, URL: %s", r.Method, r.URL.Path)
	
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Auth
	token, _, err := getVerifiedToken(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	authUID := token.UID

	// Extract conversation ID from URL path
	path := strings.TrimPrefix(r.URL.Path, "/v1/conversations/")
	conversationIDStr := strings.Split(path, "/")[0]
	conversationID, err := strconv.Atoi(conversationIDStr)
	if err != nil {
		http.Error(w, "invalid conversation ID", http.StatusBadRequest)
		return
	}

	// Mark all messages in this conversation as read
	query := `
		UPDATE message_status 
		SET read_at = NOW() 
		WHERE recipient_uid = $1 
		AND message_id IN (
			SELECT id FROM messages WHERE conversation_id = $2
		)
		AND read_at IS NULL
	`

	result, err := db.Exec(query, authUID, conversationID)
	if err != nil {
		log.Printf("markConversationAsReadHandler: database error: %v", err)
		http.Error(w, "database error", http.StatusInternalServerError)
		return
	}

	rowsAffected, _ := result.RowsAffected()
	log.Printf("Marked %d messages as read for user %s in conversation %d", rowsAffected, authUID, conversationID)


	// 🔧 FIX: Clean up offline message queue for messages that were just marked as read
	// Only mark as delivered when user has actually READ the message (not just received it)
	if rowsAffected > 0 {
		cleanupQuery := `
			UPDATE offline_message_queue 
			SET delivered = true, delivered_at = NOW()
			WHERE recipient_uid = $1 
			  AND message_id IN (
				SELECT message_id 
				FROM message_status 
				WHERE recipient_uid = $1 
				  AND read_at IS NOT NULL
				  AND message_id IN (SELECT id FROM messages WHERE conversation_id = $2)
			  )
			  AND delivered = false
		`
		
		cleanupResult, cleanupErr := db.Exec(cleanupQuery, authUID, conversationID)
		if cleanupErr != nil {
			log.Printf("markConversationAsReadHandler: failed to cleanup offline queue: %v", cleanupErr)
		} else {
			cleanupRows, _ := cleanupResult.RowsAffected()
			if cleanupRows > 0 {
				log.Printf("✅ Cleaned up %d offline queue entries for user %s (messages now read)", cleanupRows, authUID)
			}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"messages_marked": rowsAffected,
	})

// Broadcast status updates to senders for each message that was marked as read
if rowsAffected > 0 {
    // Get the message IDs and sender UIDs that were marked as read
    rows, err := db.Query(`
        SELECT DISTINCT m.id, m.sender_uid 
        FROM messages m 
        JOIN message_status ms ON m.id = ms.message_id 
        WHERE m.conversation_id = $1 AND ms.recipient_uid = $2 AND ms.read_at IS NOT NULL
    `, conversationID, authUID)
    
    if err == nil {
        defer rows.Close()
        for rows.Next() {
            var messageID int
            var senderUID string
            if err := rows.Scan(&messageID, &senderUID); err == nil {
                // Broadcast read status to the sender using your existing function
                statusMessage := map[string]interface{}{
                    "type":            "message_status",
                    "message_id":      messageID,
                    "status":          "read",
                    "conversation_id": conversationID,
                }
                broadcastToUser(globalHub, senderUID, statusMessage)
            }
        }
    }
}
}

func sessionStoreHandler(w http.ResponseWriter, r *http.Request) {
    // BYPASS AUTH FOR TESTING
    //log.Printf("DEBUG: Bypassing auth for session storage request")
    
     token, _, err := getVerifiedToken(r)
     if err != nil {
         http.Error(w, err.Error(), http.StatusUnauthorized)
        return
     }
    
    if r.Method == http.MethodPost {
        // Store session
        var req struct {
            SessionKey  string `json:"session_key"`
            SessionData string `json:"session_data"`
        }
        
        if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
            http.Error(w, "invalid json", http.StatusBadRequest)
            return
        }
        
        sessionBytes, err := base64.StdEncoding.DecodeString(req.SessionData)
        if err != nil {
            http.Error(w, "invalid base64", http.StatusBadRequest)
            return
        }
        
        _, err = db.Exec(`
            INSERT INTO shared_sessions (session_key, session_data, created_by)
            VALUES ($1, $2, $3)
            ON CONFLICT (session_key)
            DO UPDATE SET 
                session_data = EXCLUDED.session_data,
                version = shared_sessions.version + 1,
                last_updated = NOW()
        `, req.SessionKey, sessionBytes, token.UID) // Use dummy value instead of token.UID
        
        if err != nil {
            log.Printf("sessionStore error: %v", err)
            http.Error(w, "db error", http.StatusInternalServerError)
            return
        }
        
        w.WriteHeader(http.StatusOK)
        
    } else if r.Method == http.MethodGet {
        // Load session  
        sessionKey := r.URL.Query().Get("session_key")
        if sessionKey == "" {
            http.Error(w, "missing session_key", http.StatusBadRequest)
            return
        }
        
        var sessionData []byte
        err := db.QueryRow(`
            SELECT session_data FROM shared_sessions WHERE session_key = $1
        `, sessionKey).Scan(&sessionData)
        
        if err == sql.ErrNoRows {
            http.Error(w, "session not found", http.StatusNotFound)
            return
        } else if err != nil {
            http.Error(w, "db error", http.StatusInternalServerError)
            return
        }
        
        response := map[string]string{
            "session_data": base64.StdEncoding.EncodeToString(sessionData),
        }
        
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(response)
    }
}

func updatePrekeysHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	token, _, err := getVerifiedToken(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	authUID := token.UID

	var req struct {
		DeviceID       int    `json:"device_id"`
		SignedPreKey   *struct {
			KeyID        int    `json:"key_id"`
			PublicKeyB64 string `json:"public_key_b64"`
			SignatureB64 string `json:"signature_b64"`
		} `json:"signed_prekey,omitempty"`
		OneTimePreKeys []struct {
			KeyID        int    `json:"key_id"`
			PublicKeyB64 string `json:"public_key_b64"`
		} `json:"one_time_prekeys,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	if req.DeviceID <= 0 {
		http.Error(w, "device_id required", http.StatusBadRequest)
		return
	}

	tx, err := db.Begin()
	if err != nil {
		log.Printf("updatePrekeysHandler: begin tx error: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	now := time.Now().UTC()

	// Update signed prekey if provided
	if req.SignedPreKey != nil {
		signedPreKeyPub, err := base64.StdEncoding.DecodeString(req.SignedPreKey.PublicKeyB64)
		if err != nil {
			http.Error(w, "invalid signed prekey", http.StatusBadRequest)
			return
		}
		
		signedPreKeySig, err := base64.StdEncoding.DecodeString(req.SignedPreKey.SignatureB64)
		if err != nil {
			http.Error(w, "invalid signature", http.StatusBadRequest)
			return
		}

		_, err = tx.Exec(`
			INSERT INTO signed_pre_keys (key_id, firebase_uid, device_id, public_key, signature, created_at)
			VALUES ($1, $2, $3, $4, $5, $6)
			ON CONFLICT (firebase_uid, device_id, key_id) DO UPDATE
			SET public_key = EXCLUDED.public_key,
				signature = EXCLUDED.signature,
				created_at = EXCLUDED.created_at
		`, req.SignedPreKey.KeyID, authUID, req.DeviceID, signedPreKeyPub, signedPreKeySig, now)
		
		if err != nil {
			log.Printf("updatePrekeysHandler: update signed prekey error: %v", err)
			http.Error(w, "db error", http.StatusInternalServerError)
			return
		}
	}

	// Add one-time prekeys if provided
	insertedCount := 0
	if len(req.OneTimePreKeys) > 0 {
		stmt, err := tx.Prepare(`
			INSERT INTO one_time_pre_keys (key_id, firebase_uid, device_id, public_key, consumed, created_at)
			VALUES ($1, $2, $3, $4, false, $5)
			ON CONFLICT (firebase_uid, device_id, key_id) DO NOTHING
		`)
		if err != nil {
			http.Error(w, "prepare error", http.StatusInternalServerError)
			return
		}
		defer stmt.Close()

		for _, otp := range req.OneTimePreKeys {
			pub, err := base64.StdEncoding.DecodeString(otp.PublicKeyB64)
			if err != nil {
				continue
			}
			res, _ := stmt.Exec(otp.KeyID, authUID, req.DeviceID, pub, now)
			if ra, _ := res.RowsAffected(); ra > 0 {
				insertedCount++
			}
		}
	}

	if err := tx.Commit(); err != nil {
		http.Error(w, "commit error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"signed_prekey_updated": req.SignedPreKey != nil,
		"one_time_prekeys_added": insertedCount,
		"message": "prekeys updated",
	})
}

func getUserDeviceHandler(w http.ResponseWriter, r *http.Request) {
    // ADD AUTH CHECK:
    token, _, err := getVerifiedToken(r)
    if err != nil {
        log.Printf("getUserDeviceHandler: Auth failed: %v", err)
        http.Error(w, err.Error(), http.StatusUnauthorized)
        return
    }
    _ = token // We have the token but don't need the caller's UID
    
    vars := mux.Vars(r)
    targetUID := vars["uid"]
    
    // Query your devices table
    var deviceID int
    err = db.QueryRow("SELECT device_id FROM devices WHERE firebase_uid = $1 LIMIT 1", targetUID).Scan(&deviceID)
    
    if err != nil {
        if err == sql.ErrNoRows {
            http.Error(w, "User device not found", 404)
        } else {
            http.Error(w, "Database error", http.StatusInternalServerError)
        }
        return
    }
    
    json.NewEncoder(w).Encode(map[string]interface{}{
        "device_id": deviceID,
        "status": "active",
    })
}

func deliverOfflineMessages(client *Client) {
    // Query offline messages for this user (both regular messages and deletion notifications)
    // Skip regular messages if a deletion notification exists for the same message_id
    // Include attachment metadata from message_attachments table
    rows, err := db.Query(`
        SELECT omq.id as queue_id,
               COALESCE(omq.message_type, m.message_type, 'chat') as message_type,
               omq.message_data,
               omq.message_id, omq.sender_uid, omq.conversation_id, omq.encrypted_content,
               omq.session_context, omq.created_at, p.username as sender_username,
               ma.id as attachment_id,
               ma.file_type as attachment_type,
               c.is_group,
               EXISTS(
                   SELECT 1 FROM offline_message_queue omq2
                   WHERE omq2.recipient_uid = $1
                   AND omq2.message_id = omq.message_id
                   AND omq2.message_type = 'message_deleted'
                   AND omq2.delivered = false
               ) as has_deletion
        FROM offline_message_queue omq
        LEFT JOIN profiles p ON p.firebase_uid = omq.sender_uid
        LEFT JOIN messages m ON m.id = omq.message_id
        LEFT JOIN message_attachments ma ON ma.message_id = omq.message_id
        LEFT JOIN conversations c ON c.id = omq.conversation_id
        WHERE omq.recipient_uid = $1 AND omq.delivered = false
        ORDER BY omq.created_at ASC
    `, client.uid)
    
    if err != nil {
        log.Printf("deliverOfflineMessages: query error for %s: %v", client.uid, err)
        return
    }
    defer rows.Close()

    var deliveredIDs []int
    messageCount := 0

	deviceIdCache := make(map[string]int)

for rows.Next() {
    var queueID int
    var messageType sql.NullString
    var messageData []byte
    var messageID sql.NullInt64
    var senderUID sql.NullString
    var conversationID sql.NullInt64
    var encryptedContent []byte
    var sessionContext []byte
    var createdAt time.Time
    var senderUsername sql.NullString
    var attachmentID sql.NullInt64
    var attachmentType sql.NullString
    var isGroup bool
    var hasDeletion bool

    err := rows.Scan(&queueID, &messageType, &messageData,
                    &messageID, &senderUID, &conversationID, &encryptedContent,
                    &sessionContext, &createdAt, &senderUsername, &attachmentID, &attachmentType, &isGroup, &hasDeletion)
    if err != nil {
        log.Printf("deliverOfflineMessages: scan error: %v", err)
        continue
    }

    // Skip regular messages if a deletion notification exists for this message
    if hasDeletion && (!messageType.Valid || messageType.String != "message_deleted") {
        log.Printf("Skipping message %d delivery - deletion notification exists", messageID.Int64)
        // Still mark as delivered so it doesn't reappear
        deliveredIDs = append(deliveredIDs, queueID)
        continue
    }

    var wsMessage map[string]interface{}

    // Check if this is a message_deleted or attachment_uploaded notification
    if messageType.Valid && (messageType.String == "message_deleted" || messageType.String == "attachment_uploaded") && len(messageData) > 0 {
        // Unmarshal the stored JSON
        err = json.Unmarshal(messageData, &wsMessage)
        if err != nil {
            log.Printf("deliverOfflineMessages: failed to unmarshal %s data: %v", messageType.String, err)
            continue
        }
        log.Printf("Delivering offline %s notification to %s", messageType.String, client.uid)
    } else if senderUID.Valid {
        // Regular message
        actualSenderDeviceId, exists := deviceIdCache[senderUID.String]
        if !exists {
            err = db.QueryRow("SELECT device_id FROM devices WHERE firebase_uid = $1 LIMIT 1", senderUID.String).Scan(&actualSenderDeviceId)
            if err != nil {
                log.Printf("Could not get sender device ID for %s: %v", senderUID.String, err)
                actualSenderDeviceId = 1
            }
            deviceIdCache[senderUID.String] = actualSenderDeviceId
        }

        wsMessage = map[string]interface{}{
            "type":               "new_message",
            "message_id":         int(messageID.Int64),
            "conversation_id":    int(conversationID.Int64),
            "sender_uid":         senderUID.String,
            "sender_username":    senderUsername.String,
            "sender_device_id":   actualSenderDeviceId,
            "content_b64":        base64.StdEncoding.EncodeToString(encryptedContent),
            "created_at":         createdAt.UTC().Format(time.RFC3339),
            "from_offline_queue": true,
            "message_type":       messageType.String,
            "is_group":           isGroup,
        }
//         log.Printf("DEBUG Offline: Delivering message with is_group=%v for conversation %d", isGroup, int(conversationID.Int64))

        // Include attachment metadata if present
        if attachmentID.Valid {
            wsMessage["attachment_id"] = int(attachmentID.Int64)
            wsMessage["has_attachment"] = 1
            if attachmentType.Valid {
                wsMessage["attachment_type"] = attachmentType.String
            }
        }

        if sessionContext != nil {
            wsMessage["session_context_b64"] = base64.StdEncoding.EncodeToString(sessionContext)
        }
    } else {
        // Skip invalid entries
        continue
    }

    // Send via WebSocket
    messageBytes, _ := json.Marshal(wsMessage)
    select {
    case client.send <- messageBytes:
        deliveredIDs = append(deliveredIDs, queueID)
        messageCount++
        msgType := "message"
        if messageType.Valid {
            msgType = messageType.String
        }
        log.Printf("Delivered offline %s (queue_id:%d) to %s via WebSocket", msgType, queueID, client.uid)
    default:
        log.Printf("Failed to deliver offline message (queue_id:%d) to %s", queueID, client.uid)
    }
}

    // Mark delivered messages as processed
// DISABLED:     if len(deliveredIDs) > 0 {
// DISABLED:         placeholders := make([]string, len(deliveredIDs))
// DISABLED:         args := make([]interface{}, len(deliveredIDs))
// DISABLED:         for i, id := range deliveredIDs {
// DISABLED:             placeholders[i] = "$" + strconv.Itoa(i+1)
// DISABLED:             args[i] = id
// DISABLED:         }
// DISABLED: 
// DISABLED:         updateQuery := `UPDATE offline_message_queue SET delivered = true, delivered_at = NOW() 
// DISABLED:                        WHERE id IN (` + strings.Join(placeholders, ",") + `)`
// DISABLED:         
// DISABLED:         _, err = db.Exec(updateQuery, args...)
// DISABLED:         if err != nil {
// DISABLED:             log.Printf("deliverOfflineMessages: failed to mark as delivered: %v", err)
// DISABLED:         } else {
// DISABLED:             log.Printf("Delivered %d offline messages to %s", messageCount, client.uid)
// DISABLED:         }
// DISABLED:     }
}

func getPreKeyCountHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get Firebase token for authentication
	token, _, err := getVerifiedToken(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	authUID := token.UID

	// Get URL parameters
	vars := mux.Vars(r)
	uid := vars["uid"]
	deviceIdStr := vars["deviceId"]

	// Validate that user can only check their own keys
	if authUID != uid {
		http.Error(w, "unauthorized: can only check own prekeys", http.StatusForbidden)
		return
	}

	// Parse device ID
	deviceId, err := strconv.Atoi(deviceIdStr)
	if err != nil {
		http.Error(w, "invalid device ID", http.StatusBadRequest)
		return
	}

	// Query remaining prekey count
	var totalPrekeys, remainingPrekeys, consumedPrekeys int
	
	// Get total prekeys
	err = db.QueryRow(`
		SELECT COUNT(*) 
		FROM one_time_pre_keys 
		WHERE firebase_uid = $1 AND device_id = $2
	`, uid, deviceId).Scan(&totalPrekeys)
	
	if err != nil {
		log.Printf("getPreKeyCountHandler: total count query error: %v", err)
		http.Error(w, "database error", http.StatusInternalServerError)
		return
	}

	// Get remaining (unconsumed) prekeys
	err = db.QueryRow(`
		SELECT COUNT(*) 
		FROM one_time_pre_keys 
		WHERE firebase_uid = $1 AND device_id = $2 AND consumed = FALSE
	`, uid, deviceId).Scan(&remainingPrekeys)
	
	if err != nil {
		log.Printf("getPreKeyCountHandler: remaining count query error: %v", err)
		http.Error(w, "database error", http.StatusInternalServerError)
		return
	}

	// Get consumed prekeys
	err = db.QueryRow(`
		SELECT COUNT(*) 
		FROM one_time_pre_keys 
		WHERE firebase_uid = $1 AND device_id = $2 AND consumed = TRUE
	`, uid, deviceId).Scan(&consumedPrekeys)
	
	if err != nil {
		log.Printf("getPreKeyCountHandler: consumed count query error: %v", err)
		http.Error(w, "database error", http.StatusInternalServerError)
		return
	}

	// Prepare response
	response := map[string]interface{}{
		"firebase_uid":     uid,
		"device_id":        deviceId,
		"total":           totalPrekeys,
		"remaining":       remainingPrekeys,
		"consumed":        consumedPrekeys,
		"usage_percent":   0.0,
		"rotation_status": "HEALTHY",
	}

	// Calculate usage percentage
	if totalPrekeys > 0 {
		response["usage_percent"] = float64(consumedPrekeys) / float64(totalPrekeys) * 100
	}

	// Determine rotation status
	if remainingPrekeys < 20 {
		response["rotation_status"] = "NEEDS_ROTATION"
	} else if remainingPrekeys < 50 {
		response["rotation_status"] = "ROTATION_SOON"
	}

	// Log the result for debugging
	log.Printf("PreKey count for %s:%d - Total: %d, Remaining: %d, Consumed: %d", 
		uid, deviceId, totalPrekeys, remainingPrekeys, consumedPrekeys)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
