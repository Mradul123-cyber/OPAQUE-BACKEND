package main

import (
	"database/sql"
	"log"
	"os"
	"fmt"
	"path/filepath"
	"time"

	"github.com/lib/pq"
)

const (
	// Safety buffer - never delete recent media (even if both viewed)
	safetyBufferDays = 3  // 3 days - balanced approach

	// Maximum retention - delete even if unviewed (prevent infinite storage)
	maxRetentionDays = 180

	// Call logs retention - delete after 30 days for privacy
	callLogsRetentionDays = 30

	// Text messages retention - delete after 45 days
	textMessagesRetentionDays = 45
)

// startCleanupJob starts a background goroutine that periodically cleans up old media
func startCleanupJob(db *sql.DB) {
	// Run cleanup immediately on startup
	go performCleanup(db)

	// Schedule cleanup to run daily at 3 AM
	go func() {
		for {
			now := time.Now()
			// Calculate next 3 AM
			next3AM := time.Date(now.Year(), now.Month(), now.Day(), 3, 0, 0, 0, now.Location())
			if now.After(next3AM) {
				// If it's already past 3 AM today, schedule for tomorrow
				next3AM = next3AM.Add(24 * time.Hour)
			}

			// Sleep until 3 AM
			durationUntil3AM := next3AM.Sub(now)
			log.Printf("Cleanup job scheduled for: %s (in %v)", next3AM.Format("2006-01-02 15:04:05"), durationUntil3AM)
			time.Sleep(durationUntil3AM)

			// Run cleanup
			performCleanup(db)
		}
	}()

	log.Println("✅ Cleanup job started (media + messages + call logs, runs daily at 3 AM)")
}

// performCleanup deletes old media, messages, and call logs based on smart rules
func performCleanup(db *sql.DB) {
	log.Println("🧹 Starting smart cleanup job (media + messages + call logs)...")

	_ = cleanupMediaType(db, "image")
	_ = cleanupMediaType(db, "video")
	_ = cleanupTextMessages(db)
	_ = cleanupCallLogs(db)

// 	log.Printf("✅ Cleanup completed: %d images deleted, %d videos deleted, %d messages deleted, %d call logs deleted", imagesDeleted, videosDeleted, messagesDeleted, callLogsDeleted)
}

// cleanupMediaType deletes media files based on smart rules
func cleanupMediaType(db *sql.DB, fileType string) int {
	safetyDate := time.Now().AddDate(0, 0, -safetyBufferDays)
	maxRetentionDate := time.Now().AddDate(0, 0, -maxRetentionDays)

	// Smart deletion query:
	// Delete if:
	//   1. Both sender AND recipient viewed (any age, except within safety buffer)
	//   OR
	//   2. Unviewed but older than max retention (180 days)
	// AND NEVER delete if created within safety buffer (7 days)
	query := `
		SELECT id, encrypted_file_path, created_at, sender_viewed_at, recipient_viewed_at
		FROM message_attachments
		WHERE file_type = $1
		  AND created_at < $2  -- Must be older than safety buffer
		  AND (
		    -- Case 1: Both viewed (delete immediately after safety buffer)
		    (sender_viewed_at IS NOT NULL
		     AND recipient_viewed_at IS NOT NULL)
		    OR
		    -- Case 2: Unviewed but past max retention
		    (created_at < $3)
		  )
	`

	rows, err := db.Query(query, fileType, safetyDate, maxRetentionDate)
	if err != nil {
		log.Printf("❌ Error querying old %s files: %v", fileType, err)
		return 0
	}
	defer rows.Close()

	deletedCount := 0
	var attachmentIDs []int

	for rows.Next() {
		var id int
		var filePath string
		var createdAt time.Time
		var senderViewedAt, recipientViewedAt *time.Time

		if err := rows.Scan(&id, &filePath, &createdAt, &senderViewedAt, &recipientViewedAt); err != nil {
			log.Printf("❌ Error scanning attachment row: %v", err)
			continue
		}

		// Determine deletion reason for logging
		var reason string
		var ageInfo string
		if senderViewedAt != nil && recipientViewedAt != nil {
			daysSinceLastView := int(time.Since(*recipientViewedAt).Hours() / 24)
			if senderViewedAt.After(*recipientViewedAt) {
				daysSinceLastView = int(time.Since(*senderViewedAt).Hours() / 24)
			}
			reason = "both viewed"
			ageInfo = fmt.Sprintf("%d days since last view", daysSinceLastView)
		} else {
			daysSinceCreation := int(time.Since(createdAt).Hours() / 24)
			reason = "exceeded max retention (unviewed)"
			ageInfo = fmt.Sprintf("%d days old", daysSinceCreation)
		}

		// Delete physical file
		fullPath := filepath.Join(uploadsDir, filePath)
		if err := os.Remove(fullPath); err != nil {
			if !os.IsNotExist(err) {
				log.Printf("⚠️ Failed to delete file %s: %v", fullPath, err)
			}
		} else {
			log.Printf("🗑️ Deleted %s: %s (created: %s, reason: %s, %s)",
				fileType,
				filePath,
				createdAt.Format("2006-01-02"),
				reason,
				ageInfo)
		}

		attachmentIDs = append(attachmentIDs, id)
		deletedCount++
	}

	// Delete database records in batch
	if len(attachmentIDs) > 0 {
		// Use PostgreSQL array syntax with pq.Array for proper type conversion
		deleteQuery := `DELETE FROM message_attachments WHERE id = ANY($1)`
		if _, err := db.Exec(deleteQuery, pq.Array(attachmentIDs)); err != nil {
			log.Printf("❌ Error deleting attachment records from database: %v", err)
		} else {
// 			log.Printf("✅ Deleted %d %s attachment records from database", len(attachmentIDs), fileType)
		}
	}

	return deletedCount
}

// cleanupCallLogs deletes call logs older than retention period (30 days)
func cleanupCallLogs(db *sql.DB) int {
	retentionDate := time.Now().AddDate(0, 0, -callLogsRetentionDays)

	// Delete call logs older than 30 days
	query := `
		DELETE FROM call_logs
		WHERE started_at < $1
		RETURNING id
	`

	rows, err := db.Query(query, retentionDate)
	if err != nil {
		log.Printf("❌ Error deleting old call logs: %v", err)
		return 0
	}
	defer rows.Close()

	deletedCount := 0
	for rows.Next() {
		var id int
		if err := rows.Scan(&id); err != nil {
			log.Printf("❌ Error scanning deleted call log: %v", err)
			continue
		}
		deletedCount++
	}

	if deletedCount > 0 {
		log.Printf("🗑️ Deleted %d call logs older than %d days (retention date: %s)",
			deletedCount,
			callLogsRetentionDays,
			retentionDate.Format("2006-01-02"))
	}

	return deletedCount
}

// cleanupTextMessages deletes text messages older than retention period (45 days)
func cleanupTextMessages(db *sql.DB) int {
	retentionDate := time.Now().AddDate(0, 0, -textMessagesRetentionDays)

	// 1. Clean dependent records in offline_message_queue to satisfy FK constraints
	_, err := db.Exec(`
		DELETE FROM offline_message_queue 
		WHERE message_id IN (SELECT id FROM messages WHERE created_at < $1)
	`, retentionDate)
	if err != nil {
		log.Printf("⚠️ Warning: Failed to clean offline queue before message cleanup: %v", err)
	}

	// 2. Clean dependent records in message_deletions to satisfy FK constraints
	_, err = db.Exec(`
		DELETE FROM message_deletions 
		WHERE message_id IN (SELECT id FROM messages WHERE created_at < $1)
	`, retentionDate)
	if err != nil {
		log.Printf("⚠️ Warning: Failed to clean message deletions before message cleanup: %v", err)
	}

	// 3. Delete text messages older than retention days
	query := `
		DELETE FROM messages
		WHERE created_at < $1
		RETURNING id
	`

	rows, err := db.Query(query, retentionDate)
	if err != nil {
		log.Printf("❌ Error deleting old text messages: %v", err)
		return 0
	}
	defer rows.Close()

	deletedCount := 0
	for rows.Next() {
		var id int
		if err := rows.Scan(&id); err != nil {
			log.Printf("❌ Error scanning deleted message: %v", err)
			continue
		}
		deletedCount++
	}

	if deletedCount > 0 {
		log.Printf("🗑️ Deleted %d text messages older than %d days (retention date: %s)",
			deletedCount,
			textMessagesRetentionDays,
			retentionDate.Format("2006-01-02"))
	}

	return deletedCount
}
