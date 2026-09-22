package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

const (
	maxFileSize       = 100 * 1024 * 1024 // 100MB
	allowedImageTypes = "image/jpeg,image/png,image/jpg,image/gif,image/webp"
	allowedVideoTypes = "video/mp4,video/quicktime,video/x-msvideo,video/x-matroska"
	allowedAudioTypes = "audio/aac,audio/mp4,audio/mpeg,audio/ogg,audio/wav,audio/webm,audio/x-m4a"
	allowedDocumentTypes = "application/pdf,application/vnd.openxmlformats-officedocument.wordprocessingml.document,application/msword,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet,application/vnd.ms-excel,application/vnd.openxmlformats-officedocument.presentationml.presentation,application/vnd.ms-powerpoint,application/zip,application/x-rar-compressed,text/plain,text/csv,application/x-zip-compressed"
)

var uploadsDir = "./uploads"

// Initialize uploads directory for encrypted chat attachments
func initUploadsDirectory() {
	if envDir := os.Getenv("UPLOADS_DIR"); envDir != "" {
		uploadsDir = envDir
	}
	if err := os.MkdirAll(uploadsDir, 0755); err != nil {
		log.Fatal("Failed to create uploads directory: ", err)
	}
	log.Println("Uploads directory initialized at:", uploadsDir)
}

// Validate file type based on MIME type and file type category
func isValidFileType(fileType, mimeType string) bool {
	switch fileType {
	case "image":
		return contains(allowedImageTypes, mimeType)
	case "video":
		return contains(allowedVideoTypes, mimeType)
	case "audio":
		return contains(allowedAudioTypes, mimeType)
	case "document":
		return contains(allowedDocumentTypes, mimeType)
	default:
		return false
	}
}

// Helper function to check if a comma-separated list contains a value
func contains(list, value string) bool {
	for _, item := range strings.Split(list, ",") {
		if strings.TrimSpace(item) == value {
			return true
		}
	}
	return false
}

// Upload file handler - receives encrypted file from client
func uploadFileHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Auth
	token, _, err := getVerifiedToken(r)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Parse multipart form (max 101MB to accommodate 100MB file + metadata)
	if err := r.ParseMultipartForm(101 * 1024 * 1024); err != nil {
		log.Printf("Failed to parse multipart form: %v", err)
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	// Get file from form
	file, header, err := r.FormFile("file")
	if err != nil {
		log.Printf("Failed to get file from form: %v", err)
		http.Error(w, "No file provided", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Get metadata
	messageID := r.FormValue("message_id")
	fileType := r.FormValue("file_type")       // 'image', 'video', etc.
	mimeType := r.FormValue("mime_type")       // 'image/jpeg', etc.
	width := r.FormValue("width")              // for images
	height := r.FormValue("height")            // for images
	conversationID := r.FormValue("conversation_id")
	mediaEncryptionKey := r.FormValue("media_encryption_key") // Signal-encrypted AES key for recipient
	mediaEncryptionIv := r.FormValue("media_encryption_iv")   // AES IV
	// NOTE: sender_media_encryption_key is NOT stored on server (Option 1: local-only storage for security)

	// DEBUG: Log encryption metadata
// 	log.Printf("DEBUG Upload - messageID: %s", messageID)
// 	log.Printf("DEBUG Upload - mediaEncryptionKey length: %d", len(mediaEncryptionKey))
// 	log.Printf("DEBUG Upload - mediaEncryptionIv length: %d", len(mediaEncryptionIv))
	if mediaEncryptionKey != "" {
// 		log.Printf("DEBUG Upload - Encryption key received: %s...", mediaEncryptionKey[:20])
	} else {
// 		log.Printf("DEBUG Upload - ⚠️ NO encryption key received from client!")
	}

	// Validate required fields
	if messageID == "" || fileType == "" || mimeType == "" || conversationID == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	// Validate file type and MIME type
	if !isValidFileType(fileType, mimeType) {
		http.Error(w, fmt.Sprintf("Invalid file type '%s' or MIME type '%s'", fileType, mimeType), http.StatusBadRequest)
		return
	}

	msgID, err := strconv.Atoi(messageID)
	if err != nil {
		http.Error(w, "Invalid message_id", http.StatusBadRequest)
		return
	}

	convID, err := strconv.Atoi(conversationID)
	if err != nil {
		http.Error(w, "Invalid conversation_id", http.StatusBadRequest)
		return
	}

	// Verify user is member of conversation
	var isMember bool
	err = db.QueryRow(`SELECT EXISTS(SELECT 1 FROM conversation_members WHERE conversation_id = $1 AND profile_uid = $2)`,
		convID, token.UID).Scan(&isMember)
	if err != nil || !isMember {
		http.Error(w, "Not a member of conversation", http.StatusForbidden)
		return
	}

	// Verify message belongs to user
	var messageSenderUID string
	err = db.QueryRow(`SELECT sender_uid FROM messages WHERE id = $1`, msgID).Scan(&messageSenderUID)
	if err != nil {
		http.Error(w, "Message not found", http.StatusNotFound)
		return
	}
	if messageSenderUID != token.UID {
		http.Error(w, "Message does not belong to you", http.StatusForbidden)
		return
	}

	// Check file size
	if header.Size > maxFileSize {
		http.Error(w, fmt.Sprintf("File too large (max %dMB)", maxFileSize/(1024*1024)), http.StatusBadRequest)
		return
	}

	// Generate unique filename: <timestamp>_<messageID>_<originalname>
	timestamp := time.Now().Unix()
	safeFilename := fmt.Sprintf("%d_%d_%s", timestamp, msgID, filepath.Base(header.Filename))
	filePath := filepath.Join(uploadsDir, safeFilename)

	// Create file on disk
	dst, err := os.Create(filePath)
	if err != nil {
		log.Printf("Failed to create file: %v", err)
		http.Error(w, "Failed to save file", http.StatusInternalServerError)
		return
	}
	defer dst.Close()

	// Copy encrypted file content
	written, err := io.Copy(dst, file)
	if err != nil {
		log.Printf("Failed to write file: %v", err)
		http.Error(w, "Failed to save file", http.StatusInternalServerError)
		return
	}

	log.Printf("File saved: %s, size: %d bytes", filePath, written)

	// Parse optional dimensions
	var widthInt, heightInt *int
	if width != "" {
		if w, err := strconv.Atoi(width); err == nil {
			widthInt = &w
		}
	}
	if height != "" {
		if h, err := strconv.Atoi(height); err == nil {
			heightInt = &h
		}
	}

	// Save metadata to database (including encryption metadata)
	// NOTE: Set sender_viewed_at = NOW() on upload (sender has already "viewed" it by sending)
	var attachmentID int
	var mediaKeyPtr, mediaIvPtr *string
	if mediaEncryptionKey != "" {
		mediaKeyPtr = &mediaEncryptionKey
	}
	if mediaEncryptionIv != "" {
		mediaIvPtr = &mediaEncryptionIv
	}

	err = db.QueryRow(`
		INSERT INTO message_attachments (message_id, file_type, mime_type, file_size, encrypted_file_path, width, height, media_encryption_key, media_encryption_iv, sender_viewed_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
		RETURNING id
	`, msgID, fileType, mimeType, written, safeFilename, widthInt, heightInt, mediaKeyPtr, mediaIvPtr).Scan(&attachmentID)

	if err != nil {
		log.Printf("Failed to save attachment metadata: %v", err)
		// Clean up file
		os.Remove(filePath)
		http.Error(w, "Failed to save metadata", http.StatusInternalServerError)
		return
	}

	log.Printf("Attachment %d created for message %d by user %s (sender_viewed_at set)", attachmentID, msgID, token.UID)

	// Get sender_device_id from the message
	var senderDeviceID int
	err = db.QueryRow(`SELECT sender_device_id FROM messages WHERE id = $1`, msgID).Scan(&senderDeviceID)
	if err != nil {
		log.Printf("Warning: Failed to get sender_device_id for message %d: %v", msgID, err)
		senderDeviceID = 1 // Default fallback
	}

	// Broadcast attachment notification to conversation members
	attachmentPayload := map[string]interface{}{
		"type":            "attachment_uploaded",
		"message_id":      msgID,
		"attachment_id":   attachmentID,
		"conversation_id": convID,
		"file_type":       fileType,
		"mime_type":       mimeType,
		"file_size":       written,
		"width":           widthInt,
		"height":          heightInt,
		"uploaded_by":     token.UID,
		"sender_device_id": senderDeviceID,
	}

	// Add encryption metadata if present
	if mediaEncryptionKey != "" {
		attachmentPayload["media_encryption_key"] = mediaEncryptionKey
// 		log.Printf("DEBUG Broadcast - Added media_encryption_key to payload")
	} else {
// 		log.Printf("DEBUG Broadcast - ⚠️ mediaEncryptionKey is empty, not adding to payload")
	}
	if mediaEncryptionIv != "" {
		attachmentPayload["media_encryption_iv"] = mediaEncryptionIv
// 		log.Printf("DEBUG Broadcast - Added media_encryption_iv to payload")
	} else {
// 		log.Printf("DEBUG Broadcast - ⚠️ mediaEncryptionIv is empty, not adding to payload")
	}
	// NOTE: sender_media_encryption_key is NOT sent in broadcast (stored locally on client only)

	// DEBUG: Log the full payload being broadcast
	payloadKeys := make([]string, 0, len(attachmentPayload))
	for key := range attachmentPayload {
		payloadKeys = append(payloadKeys, key)
	}
// 	log.Printf("DEBUG Broadcast - Full payload keys: %v", payloadKeys)

	// Get conversation members and broadcast
	memberUIDs, err := getConversationMemberUIDs(db, convID)
	if err == nil {
		for _, uid := range memberUIDs {
			broadcastToUser(globalHub, uid, attachmentPayload)
		}
		log.Printf("Broadcasted attachment upload to %d members", len(memberUIDs))
	}

	// Return success with file info
	w.Header().Set("Content-Type", "application/json")
	response := map[string]interface{}{
		"attachment_id": attachmentID,
		"message_id":    msgID,
		"file_size":     written,
		"file_type":     fileType,
	}

	// Include encryption metadata in response
	if mediaEncryptionKey != "" {
		response["media_encryption_key"] = mediaEncryptionKey
// 		log.Printf("DEBUG Response - Added media_encryption_key to HTTP response")
	}
	if mediaEncryptionIv != "" {
		response["media_encryption_iv"] = mediaEncryptionIv
// 		log.Printf("DEBUG Response - Added media_encryption_iv to HTTP response")
	}
	// NOTE: sender_media_encryption_key is NOT returned in response (stored locally on client only)

	// DEBUG: Log response keys
	responseKeys := make([]string, 0, len(response))
	for key := range response {
		responseKeys = append(responseKeys, key)
	}
// 	log.Printf("DEBUG Response - HTTP response keys: %v", responseKeys)

	json.NewEncoder(w).Encode(response)
}

// Get attachment metadata handler - returns encryption metadata without file content
func getAttachmentMetadataHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Auth
	token, _, err := getVerifiedToken(r)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Get file ID from URL
	vars := mux.Vars(r)
	fileIDStr := vars["fileId"]
	fileID, err := strconv.Atoi(fileIDStr)
	if err != nil {
		http.Error(w, "Invalid file ID", http.StatusBadRequest)
		return
	}

	// Get attachment metadata from database
	var messageID int
	var conversationID int
	var fileType string
	var mimeType string
	var fileSize int64
	var width, height *int
	var mediaEncryptionKey, mediaEncryptionIv *string
	var senderDeviceID int

	err = db.QueryRow(`
		SELECT ma.message_id, m.conversation_id, ma.file_type, ma.mime_type, ma.file_size,
		       ma.width, ma.height, ma.media_encryption_key, ma.media_encryption_iv, m.sender_device_id
		FROM message_attachments ma
		JOIN messages m ON m.id = ma.message_id
		WHERE ma.id = $1
	`, fileID).Scan(&messageID, &conversationID, &fileType, &mimeType, &fileSize,
		&width, &height, &mediaEncryptionKey, &mediaEncryptionIv, &senderDeviceID)

	if err != nil {
		log.Printf("Attachment metadata not found: %v", err)
		http.Error(w, "Attachment not found", http.StatusNotFound)
		return
	}

	// Verify user is member of conversation
	var isMember bool
	err = db.QueryRow(`SELECT EXISTS(SELECT 1 FROM conversation_members WHERE conversation_id = $1 AND profile_uid = $2)`,
		conversationID, token.UID).Scan(&isMember)
	if err != nil || !isMember {
		http.Error(w, "Not authorized to access this attachment", http.StatusForbidden)
		return
	}

	// Return metadata as JSON
	w.Header().Set("Content-Type", "application/json")
	response := map[string]interface{}{
		"attachment_id": fileID,
		"message_id":    messageID,
		"file_type":     fileType,
		"mime_type":     mimeType,
		"file_size":     fileSize,
		"sender_device_id": senderDeviceID,
	}

	if width != nil {
		response["width"] = *width
	}
	if height != nil {
		response["height"] = *height
	}
	if mediaEncryptionKey != nil {
		response["media_encryption_key"] = *mediaEncryptionKey
	}
	if mediaEncryptionIv != nil {
		response["media_encryption_iv"] = *mediaEncryptionIv
	}
	// NOTE: sender_media_encryption_key is NOT stored on server (stored locally on client only)

	json.NewEncoder(w).Encode(response)
	log.Printf("Attachment metadata %d fetched by user %s", fileID, token.UID)
}

// Download file handler - returns encrypted file to client
func downloadFileHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Auth
	token, _, err := getVerifiedToken(r)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Get file ID from URL
	vars := mux.Vars(r)
	fileIDStr := vars["fileId"]
	fileID, err := strconv.Atoi(fileIDStr)
	if err != nil {
		http.Error(w, "Invalid file ID", http.StatusBadRequest)
		return
	}

	// Get file metadata from database
	var messageID int
	var conversationID int
	var filePath string
	var mimeType string
	var fileSize int64
	var senderUID string

	err = db.QueryRow(`
		SELECT ma.message_id, m.conversation_id, ma.encrypted_file_path, ma.mime_type, ma.file_size, m.sender_uid
		FROM message_attachments ma
		JOIN messages m ON m.id = ma.message_id
		WHERE ma.id = $1
	`, fileID).Scan(&messageID, &conversationID, &filePath, &mimeType, &fileSize, &senderUID)

	if err != nil {
		log.Printf("File not found: %v", err)
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	// Verify user is member of conversation
	var isMember bool
	err = db.QueryRow(`SELECT EXISTS(SELECT 1 FROM conversation_members WHERE conversation_id = $1 AND profile_uid = $2)`,
		conversationID, token.UID).Scan(&isMember)
	if err != nil || !isMember {
		http.Error(w, "Not authorized to access this file", http.StatusForbidden)
		return
	}

	// Track download: Update sender_viewed_at or recipient_viewed_at
	isSender := token.UID == senderUID
	if isSender {
		// Sender downloading their own media
		_, err = db.Exec(`UPDATE message_attachments SET sender_viewed_at = NOW() WHERE id = $1 AND sender_viewed_at IS NULL`, fileID)
		if err != nil {
			log.Printf("Warning: Failed to update sender_viewed_at for attachment %d: %v", fileID, err)
		} else {
			log.Printf("Tracked sender view for attachment %d", fileID)
		}
	} else {
		// Recipient downloading media
		_, err = db.Exec(`UPDATE message_attachments SET recipient_viewed_at = NOW() WHERE id = $1 AND recipient_viewed_at IS NULL`, fileID)
		if err != nil {
			log.Printf("Warning: Failed to update recipient_viewed_at for attachment %d: %v", fileID, err)
		} else {
			log.Printf("Tracked recipient view for attachment %d", fileID)
		}
	}

	// Open file
	fullPath := filepath.Join(uploadsDir, filePath)
	file, err := os.Open(fullPath)
	if err != nil {
		log.Printf("Failed to open file %s: %v", fullPath, err)
		http.Error(w, "File not found on server", http.StatusNotFound)
		return
	}
	defer file.Close()

	// Set headers
	w.Header().Set("Content-Type", "application/octet-stream") // Send as binary (encrypted)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", fileSize))
	w.Header().Set("X-File-Type", mimeType) // Original mime type in header
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filepath.Base(filePath)))

	// Stream file to client
	written, err := io.Copy(w, file)
	if err != nil {
		log.Printf("Error streaming file: %v", err)
		return
	}

	log.Printf("File %d downloaded by user %s (%d bytes)", fileID, token.UID, written)
}