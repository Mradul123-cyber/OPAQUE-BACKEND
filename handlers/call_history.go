package handlers

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"time"
)

type CallLog struct {
	ID             int       `json:"id"`
	CallerUID      string    `json:"caller_uid"`
	ReceiverUID    string    `json:"receiver_uid"`
	CallType       string    `json:"call_type"`
	CallStatus     string    `json:"call_status"`
	ConversationID *int      `json:"conversation_id"`
	StartedAt      time.Time `json:"started_at"`
	EndedAt        *time.Time `json:"ended_at"`
	DurationSeconds *int     `json:"duration_seconds"`

	// Additional fields for UI
	OtherUserUID  string  `json:"other_user_uid"`   // The other person in the call
	OtherUserName string  `json:"other_user_name"`  // Their name
	OtherUserAvatar *string `json:"other_user_avatar"` // Their avatar
	Direction     string  `json:"direction"`        // "incoming" or "outgoing"
}

// GetCallHistory returns call history for a user
func GetCallHistory(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get user UID from query parameter
		userUID := r.URL.Query().Get("uid")
		if userUID == "" {
			http.Error(w, "Missing uid parameter", http.StatusBadRequest)
			return
		}

		// Optional limit parameter (default 50)
		limit := r.URL.Query().Get("limit")
		if limit == "" {
			limit = "50"
		}

		// Query call logs with user details
		query := `
			SELECT
				cl.id,
				cl.caller_uid,
				cl.receiver_uid,
				cl.call_type,
				cl.call_status,
				cl.conversation_id,
				cl.started_at,
				cl.ended_at,
				cl.duration_seconds,
				CASE
					WHEN cl.caller_uid = $1 THEN cl.receiver_uid
					ELSE cl.caller_uid
				END as other_user_uid,
				CASE
					WHEN cl.caller_uid = $1 THEN COALESCE(NULLIF(p2.display_name, ''), p2.username)
					ELSE COALESCE(NULLIF(p1.display_name, ''), p1.username)
				END as other_user_name,
				CASE
					WHEN cl.caller_uid = $1 THEN p2.profile_avatar_url
					ELSE p1.profile_avatar_url
				END as other_user_avatar,
				CASE
					WHEN cl.caller_uid = $1 THEN 'outgoing'
					ELSE 'incoming'
				END as direction
			FROM call_logs cl
			LEFT JOIN profiles p1 ON cl.caller_uid = p1.firebase_uid
			LEFT JOIN profiles p2 ON cl.receiver_uid = p2.firebase_uid
			WHERE cl.caller_uid = $1 OR cl.receiver_uid = $1
			ORDER BY cl.started_at DESC
			LIMIT $2
		`

		rows, err := db.Query(query, userUID, limit)
		if err != nil {
			http.Error(w, "Database error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var callLogs []CallLog
		for rows.Next() {
			var log CallLog
			var otherUserAvatar sql.NullString

			err := rows.Scan(
				&log.ID,
				&log.CallerUID,
				&log.ReceiverUID,
				&log.CallType,
				&log.CallStatus,
				&log.ConversationID,
				&log.StartedAt,
				&log.EndedAt,
				&log.DurationSeconds,
				&log.OtherUserUID,
				&log.OtherUserName,
				&otherUserAvatar,
				&log.Direction,
			)

			if err != nil {
				continue
			}

			if otherUserAvatar.Valid {
				log.OtherUserAvatar = &otherUserAvatar.String
			}

			callLogs = append(callLogs, log)
		}

		// Return empty array if no calls found
		if callLogs == nil {
			callLogs = []CallLog{}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(callLogs)
	}
}
