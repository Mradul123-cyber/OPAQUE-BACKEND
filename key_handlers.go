package main

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	"firebase.google.com/go/v4/auth"
)

// verifyFirebaseToken is a helper function to authenticate a request
// and return the user's token, which contains their UID.
func verifyFirebaseToken(r *http.Request) (*auth.Token, error) {
	idToken := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if idToken == "" {
		return nil, errors.New("authorization header not found")
	}
	return firebaseAuth.VerifyIDToken(r.Context(), idToken)
}

// keysUploadHandler handles the `POST /keys` endpoint.
// It receives a full PreKeyBundle from a client and stores it in the database.
func keysUploadHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// 1. Authenticate the user
		token, err := verifyFirebaseToken(r)
		if err != nil {
			http.Error(w, "Unauthorized: Invalid token", http.StatusUnauthorized)
			return
		}
		uid := token.UID

		// 2. Decode the incoming JSON payload
		var payload PreKeyBundlePayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		log.Printf("Received key upload payload for user %s: %+v", uid, payload)


		// 3. Start a database transaction
		tx, err := db.Begin()
		if err != nil {
			log.Printf("Failed to begin transaction: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		defer tx.Rollback() // Rollback if anything fails

		// 4. Clear any old keys for this user to prevent conflicts
		_, err = tx.Exec("DELETE FROM identity_keys WHERE firebase_uid = $1", uid)
		if err != nil {
			log.Printf("Failed to delete old identity key: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		_, _ = tx.Exec("DELETE FROM signed_pre_keys WHERE firebase_uid = $1", uid)
		_, _ = tx.Exec("DELETE FROM one_time_pre_keys WHERE firebase_uid = $1", uid)
		log.Printf("Cleared old keys for user %s", uid)


		// 5. Insert the new identity key
		identityKeyBytes, err := base64.StdEncoding.DecodeString(payload.IdentityKey)
		if err != nil {
			http.Error(w, "Invalid base64 for identity key", http.StatusBadRequest)
			return
		}
		log.Printf("Inserting Identity Key for %s. Raw Bytes: %x", uid, identityKeyBytes)
		// --- NEW DEBUG LOG ADDED HERE ---
// 		log.Printf("DEBUG: Identity Key INSERT preparing. UID: %s, RegID from payload: %d", uid, payload.RegistrationID)
		// --- END NEW DEBUG LOG ---
		_, err = tx.Exec(
			"INSERT INTO identity_keys (firebase_uid, public_key, registration_id) VALUES ($1, $2, $3)",
			uid, identityKeyBytes, payload.RegistrationID,
		)
		if err != nil {
			log.Printf("Failed to insert identity key: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// --- IMMEDIATE READ AFTER WRITE FOR IDENTITY KEY ---
		var retrievedIdentityKeyBytes []byte
		var retrievedRegID int
		err = tx.QueryRow("SELECT public_key, registration_id FROM identity_keys WHERE firebase_uid = $1", uid).Scan(&retrievedIdentityKeyBytes, &retrievedRegID)
		if err != nil {
			log.Printf("ERROR: Failed to retrieve identity key immediately after insert for %s: %v", uid, err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		log.Printf("VERIFY (Identity Key): Inserted: %x, Retrieved: %x, Retrieved RegID: %d", identityKeyBytes, retrievedIdentityKeyBytes, retrievedRegID) // Added retrievedRegID
		if !bytes.Equal(identityKeyBytes, retrievedIdentityKeyBytes) {
			log.Printf("CRITICAL ERROR: Identity Key mismatch after immediate read for %s!", uid)
			http.Error(w, "Internal server error: Identity Key corruption", http.StatusInternalServerError)
			return
		}
		// --- END IMMEDIATE READ ---


		// 6. Insert the new signed pre-key
		signedKeyBytes, err := base64.StdEncoding.DecodeString(payload.SignedPreKey.PublicKey)
		if err != nil {
			http.Error(w, "Invalid base64 for signed pre-key public key", http.StatusBadRequest)
			return
		}
		signatureBytes, err := base64.StdEncoding.DecodeString(payload.SignedPreKey.Signature)
		if err != nil {
			http.Error(w, "Invalid base64 for signed pre-key signature", http.StatusBadRequest)
			return
		}
		log.Printf("Inserting Signed Pre-Key for %s. Key ID: %d. Raw PubKey: %x. Raw Sig: %x", uid, payload.SignedPreKey.ID, signedKeyBytes, signatureBytes)
		_, err = tx.Exec(
			"INSERT INTO signed_pre_keys (firebase_uid, key_id, public_key, signature) VALUES ($1, $2, $3, $4)",
			uid, payload.SignedPreKey.ID, signedKeyBytes, signatureBytes,
		)
		if err != nil {
			log.Printf("Failed to insert signed pre-key: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// --- IMMEDIATE READ AFTER WRITE FOR SIGNED PRE-KEY ---
		var retrievedSignedKeyBytes, retrievedSignatureBytes []byte
		var retrievedSignedKeyID int
		err = tx.QueryRow("SELECT key_id, public_key, signature FROM signed_pre_keys WHERE firebase_uid = $1 AND key_id = $2", uid, payload.SignedPreKey.ID).Scan(&retrievedSignedKeyID, &retrievedSignedKeyBytes, &retrievedSignatureBytes)
		if err != nil {
			log.Printf("ERROR: Failed to retrieve signed pre-key immediately after insert for %s: %v", uid, err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		log.Printf("VERIFY (Signed Pre-Key PubKey): Inserted: %x, Retrieved: %x", signedKeyBytes, retrievedSignedKeyBytes)
		if !bytes.Equal(signedKeyBytes, retrievedSignedKeyBytes) {
			log.Printf("CRITICAL ERROR: Signed Pre-Key Public Key mismatch after immediate read for %s!", uid)
			http.Error(w, "Internal server error: Signed Pre-Key PubKey corruption", http.StatusInternalServerError)
			return
		}
		log.Printf("VERIFY (Signed Pre-Key Signature): Inserted: %x, Retrieved: %x", signatureBytes, retrievedSignatureBytes)
		if !bytes.Equal(signatureBytes, retrievedSignatureBytes) {
			log.Printf("CRITICAL ERROR: Signed Pre-Key Signature mismatch after immediate read for %s!", uid)
			http.Error(w, "Internal server error: Signed Pre-Key Signature corruption", http.StatusInternalServerError)
			return
		}
		// --- END IMMEDIATE READ ---


		// 7. Insert all the one-time pre-keys
		for _, otpk := range payload.OneTimePreKeys {
			otpkBytes, err := base64.StdEncoding.DecodeString(otpk.PublicKey)
			if err != nil {
				http.Error(w, fmt.Sprintf("Invalid base64 for one-time pre-key %d", otpk.ID), http.StatusBadRequest)
				return
			}
			log.Printf("Inserting One-Time Pre-Key for %s. Key ID: %d. Raw PubKey: %x", uid, otpk.ID, otpkBytes)
			_, err = tx.Exec(
				"INSERT INTO one_time_pre_keys (firebase_uid, key_id, public_key) VALUES ($1, $2, $3)",
				uid, otpk.ID, otpkBytes,
			)
			if err != nil {
				log.Printf("Failed to insert one-time pre-key %d: %v", otpk.ID, err)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}

			// --- IMMEDIATE READ AFTER WRITE FOR ONE-TIME PRE-KEY ---
			var retrievedOtpkBytes []byte
			var retrievedOtpkID int
			var retrievedIsClaimed bool
			err = tx.QueryRow("SELECT key_id, public_key, is_claimed FROM one_time_pre_keys WHERE firebase_uid = $1 AND key_id = $2", uid, otpk.ID).Scan(&retrievedOtpkID, &retrievedOtpkBytes, &retrievedIsClaimed)
			if err != nil {
				log.Printf("ERROR: Failed to retrieve one-time pre-key %d immediately after insert for %s: %v", otpk.ID, uid, err)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}
			log.Printf("VERIFY (One-Time Pre-Key PubKey ID %d): Inserted: %x, Retrieved: %x", otpk.ID, otpkBytes, retrievedOtpkBytes)
			if !bytes.Equal(otpkBytes, retrievedOtpkBytes) {
				log.Printf("CRITICAL ERROR: One-Time Pre-Key Public Key mismatch after immediate read for %s, ID %d!", uid, otpk.ID)
				http.Error(w, "Internal server error: One-Time Pre-Key PubKey corruption", http.StatusInternalServerError)
				return
			}
			// --- END IMMEDIATE READ ---
		}

		// 8. If everything was successful, commit the transaction
		if err := tx.Commit(); err != nil {
			log.Printf("Failed to commit transaction: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusCreated)
		log.Printf("Successfully stored key bundle for user %s", uid)
	}
}

// keyBundleFetchHandler (no changes needed here for now, as the problem is on the write/read cycle)
func keyBundleFetchHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		requestingUserToken, err := verifyFirebaseToken(r)
		if err != nil {
			http.Error(w, "Unauthorized: Invalid token", http.StatusUnauthorized)
			return
		}

		targetUID := strings.TrimPrefix(r.URL.Path, "/keys/")
		if targetUID == "" {
			http.Error(w, "User ID not specified in path", http.StatusBadRequest)
			return
		}

		log.Printf("Requesting key bundle for target user %s by user %s", targetUID, requestingUserToken.UID)

		var response PreKeyBundleResponse
		var oneTimeKey *OneTimePreKeyData

		tx, err := db.Begin()
		if err != nil {
			log.Printf("Failed to begin transaction: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		defer tx.Rollback()

		var identityKeyBytes []byte
		err = tx.QueryRow("SELECT public_key, registration_id FROM identity_keys WHERE firebase_uid = $1", targetUID).Scan(&identityKeyBytes, &response.RegistrationID)
		if err != nil {
			if err == sql.ErrNoRows {
				log.Printf("Identity key not found for user %s", targetUID)
				http.Error(w, "User or identity key not found", http.StatusNotFound)
				return
			}
			log.Printf("Error fetching identity key for user %s: %v", targetUID, err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		response.IdentityKey = base64.StdEncoding.EncodeToString(identityKeyBytes)
		log.Printf("Fetched Identity Key for %s. Raw Bytes: %x, RegID: %d", targetUID, identityKeyBytes, response.RegistrationID)


		var signedKeyBytes, signatureBytes []byte
		err = tx.QueryRow("SELECT key_id, public_key, signature FROM signed_pre_keys WHERE firebase_uid = $1", targetUID).Scan(&response.SignedPreKey.ID, &signedKeyBytes, &signatureBytes)
		if err != nil {
			log.Printf("Signed pre-key not found for user %s", targetUID)
			http.Error(w, "User or signed pre-key not found", http.StatusNotFound)
			return
		}
		response.SignedPreKey.PublicKey = base64.StdEncoding.EncodeToString(signedKeyBytes)
		response.SignedPreKey.Signature = base64.StdEncoding.EncodeToString(signatureBytes)
		log.Printf("Fetched Signed Pre-Key for %s. Key ID: %d. Raw PubKey: %x. Raw Sig: %x", targetUID, response.SignedPreKey.ID, signedKeyBytes, signatureBytes)


		var otpkID int
		var otpkBytes []byte
		err = tx.QueryRow("SELECT key_id, public_key FROM one_time_pre_keys WHERE firebase_uid = $1 AND is_claimed = FALSE LIMIT 1 FOR UPDATE SKIP LOCKED", targetUID).Scan(&otpkID, &otpkBytes)
		
		if err != nil && err != sql.ErrNoRows {
			log.Printf("Error fetching one-time key for %s: %v", targetUID, err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		if err == nil {
			log.Printf("Found and claiming one-time pre-key for %s. ID: %d. Raw PubKey: %x", targetUID, otpkID, otpkBytes)
			
			_, updateErr := tx.Exec("UPDATE one_time_pre_keys SET is_claimed = TRUE WHERE firebase_uid = $1 AND key_id = $2", targetUID, otpkID)
			if updateErr != nil {
				log.Printf("Error claiming one-time key for %s: %v", targetUID, updateErr)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}
			oneTimeKey = &OneTimePreKeyData{
				ID:        otpkID,
				PublicKey: base64.StdEncoding.EncodeToString(otpkBytes),
			}
			response.OneTimePreKey = oneTimeKey
			log.Printf("One-time pre-key claimed successfully. ID: %d. Pub: %s", otpkID, oneTimeKey.PublicKey)
		} else {
			log.Printf("No one-time pre-key found for user %s. This is OK for future sessions.", targetUID)
		}
		

		if err := tx.Commit(); err != nil {
			log.Printf("Failed to commit transaction: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		
		finalResponse, marshalErr := json.Marshal(response)
		if marshalErr != nil {
			log.Printf("Error marshaling final JSON response for %s: %v", targetUID, marshalErr)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		log.Printf("Final JSON response for %s: %s", targetUID, string(finalResponse))

		w.Write(finalResponse)
		log.Printf("Successfully served key bundle for user %s", targetUID)
	}
}
