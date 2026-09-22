package main

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const (
	writeWait      = 10 * time.Second
	pongWait       = 60 * time.Second
	pingPeriod     = (pongWait * 9) / 10
	maxMessageSize = 1024 * 1024
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  131072,
	WriteBufferSize: 131072,
	CheckOrigin:     func(r *http.Request) bool { return true },
}

type Client struct {
	hub      *Hub
	conn     *websocket.Conn
	send     chan []byte
	username string
	uid      string
	db       *sql.DB
}

// HubMessage supports optional recipients (targeted messages).
type HubMessage struct {
	message    []byte
	sender     *Client
	recipients []string // if nil -> standard conversation broadcast
}

// PendingCall stores call offers and ICE candidates for offline users
type PendingCall struct {
	callerUID     string
	recipientUID  string
	callData      map[string]interface{}
	iceCandidates []map[string]interface{} // Buffer ICE candidates that arrive while offline
	timestamp     time.Time
}

  type Hub struct {
        clients        map[string]*Client
        broadcast      chan HubMessage
        register       chan *Client
        unregister     chan *Client
        updateUsername chan map[string]string
        db             *sql.DB
        pendingCalls   map[string]*PendingCall // key: recipientUID
        mu             sync.RWMutex            // Mutex for thread-safe access to clients map
        // ✅ PERFORMANCE FIX: Track recent status updates to prevent duplicates
        recentStatusUpdates map[string]time.Time // key: "messageID_recipientUID_status"
        statusMu            sync.RWMutex         // Mutex for status updates map
  }

// Simplified message struct - no manual key management
type IncomingChatMessage struct {
	ConversationID int    `json:"conversationId"`
	Content        string `json:"content"`
	ClientID       int64  `json:"clientId"`
	SenderDeviceID int    `json:"sender_device_id"`
}

// Simplified Message struct for responses
type Message struct {
	ID                int       `json:"id"`
	ConversationID    int       `json:"conversationId"`
	Username          string    `json:"username"`
	Content           string    `json:"content"`
	Timestamp         time.Time `json:"timestamp"`
	SenderUID         string    `json:"senderUid"`
	ReplyToMessageID  *int      `json:"replyToMessageId,omitempty"`
}

 func newHub(db *sql.DB) *Hub {
        return &Hub{
                broadcast:           make(chan HubMessage),
                register:            make(chan *Client),
                unregister:          make(chan *Client),
                clients:             make(map[string]*Client),
                updateUsername:      make(chan map[string]string),
                db:                  db,
                pendingCalls:        make(map[string]*PendingCall),
                recentStatusUpdates: make(map[string]time.Time), // ✅ ADD THIS LINE
        }
  }

func broadcastToUser(hub *Hub, uid string, message map[string]interface{}) {
// 	log.Printf("=== broadcastToUser ENTRY: uid=%s, type=%v ===", uid, message["type"])
//     log.Printf("DEBUG: broadcastToUser called for user %s with message type: %v", uid, message["type"])

    // DEBUG: Log is_group before marshalling
    if msgType, ok := message["type"].(string); ok && msgType == "new_message" {
//         log.Printf("DEBUG broadcastToUser - is_group BEFORE marshal: %v (type: %T)", message["is_group"], message["is_group"])
    }

    // DEBUG: Log message keys before marshalling
    if msgType, ok := message["type"].(string); ok && msgType == "attachment_uploaded" {
        keys := make([]string, 0, len(message))
        for key := range message {
            keys = append(keys, key)
        }
//         log.Printf("DEBUG broadcastToUser - Message keys BEFORE marshal: %v", keys)
//         log.Printf("DEBUG broadcastToUser - Has media_encryption_key: %v", message["media_encryption_key"] != nil)
//         log.Printf("DEBUG broadcastToUser - Has media_encryption_iv: %v", message["media_encryption_iv"] != nil)
    }

    messageBytes, err := json.Marshal(message)
    if err != nil {
        log.Printf("Error marshalling message for user %s: %v", uid, err)
        return
    }

    // DEBUG: Log marshalled JSON for new_message
    if msgType, ok := message["type"].(string); ok && msgType == "new_message" {
//         log.Printf("DEBUG broadcastToUser - Marshalled JSON: %s", string(messageBytes))
    }

    // DEBUG: Log marshalled JSON for attachment_uploaded
    if msgType, ok := message["type"].(string); ok && msgType == "attachment_uploaded" {
//         log.Printf("DEBUG broadcastToUser - Marshalled JSON: %s", string(messageBytes))
    }

    // FIXED: Direct map lookup instead of loop
    if targetClient, exists := hub.clients[uid]; exists {
        // User is online - send via WebSocket
        select {
        case targetClient.send <- messageBytes:
//             log.Printf("Message sent to user %s (%s) via WebSocket", uid, targetClient.username)
        default:
            log.Printf("Failed to send message to user %s, channel full", uid)
        }
    } else {
        // User is offline
        log.Printf("User %s not found in connected clients (total clients: %d)", uid, len(hub.clients))
        
        // Debug: Show what clients we do have
        //log.Printf("DEBUG: Current online clients:")
        //for clientUID, client := range hub.clients {
          //  log.Printf("DEBUG: - UID: %s, Username: %s", clientUID, client.username)
        //}
        
        // Handle offline message
        if messageType, ok := message["type"].(string); ok {
            switch messageType {
            case "message_status":
                queueStatusUpdateForOfflineUser(uid, message)
            case "new_message":
                sendNewMessageNotificationFromMessage(uid, message)
            case "message_deleted":
                queueDeletionForOfflineUser(uid, message)
            case "attachment_uploaded":
                queueAttachmentNotificationForOfflineUser(uid, message)
            }
        }
    }
}



func handleSessionResetNotification(hub *Hub, client *Client, data map[string]interface{}) {
	recipientUID, ok := data["recipient_uid"].(string)
	if !ok {
		log.Printf("Invalid or missing recipient_uid in session_reset_required from %s", client.username)
		return
	}

	log.Printf("Session reset notification from %s to %s", client.username, recipientUID)

	data["sender_uid"] = client.uid
	data["sender_username"] = client.username

	hub.mu.RLock()
	recipientClient, exists := hub.clients[recipientUID]
	hub.mu.RUnlock()

	if exists {
		messageBytes, err := json.Marshal(data)
		if err != nil {
			log.Printf("Error marshaling session reset notification: %v", err)
			return
		}

		select {
		case recipientClient.send <- messageBytes:
			log.Printf("Forwarded session reset notification to %s", recipientUID)
		default:
			log.Printf("Failed to forward session reset notification to %s", recipientUID)
		}
	} else {
		log.Printf("Recipient %s offline, session reset notification dropped", recipientUID)
	}
}

func handleCallSignaling(hub *Hub, client *Client, data map[string]interface{}) {
	// Get recipient UID from the message
	recipientUID, ok := data["recipient_uid"].(string)
	if !ok {
		log.Printf("Invalid or missing recipient_uid in call signaling from %s", client.username)
		return
	}

	// Add sender info to the message
	data["sender_uid"] = client.uid
	data["sender_username"] = client.username

	// Fetch and add avatar and display_name for both call_offer and call_answer
	msgType := data["type"].(string)
	if msgType == "call_offer" || msgType == "call_answer" {
		// Fetch user's profile picture and display name from database
		var avatarURL sql.NullString
		var displayName sql.NullString
		err := client.db.QueryRow("SELECT profile_avatar_url, display_name FROM profiles WHERE firebase_uid = $1", client.uid).Scan(&avatarURL, &displayName)
		if err != nil && err != sql.ErrNoRows {
			log.Printf("Error fetching profile data for %s %s (uid=%s): %v", msgType, client.username, client.uid, err)
		} else if err == sql.ErrNoRows {
// 			log.Printf("No profile found for %s %s (uid=%s)", msgType, client.username, client.uid)
		} else {
			if avatarURL.Valid {
				data["avatar_url"] = avatarURL.String
// 				log.Printf("Added avatar_url for %s from %s: %s", msgType, client.username, avatarURL.String)
			}
			if displayName.Valid {
				data["sender_display_name"] = displayName.String
// 				log.Printf("Added sender_display_name for %s from %s: %s", msgType, client.username, displayName.String)
			}
		}
	}

	// Check if recipient is online for call_offer
	if msgType == "call_offer" {
		if _, exists := hub.clients[recipientUID]; !exists {
			// Recipient is offline - send FCM notification and store pending call
			log.Printf("📵 Recipient %s is offline, sending FCM and storing pending call for 30s", recipientUID)

			// Send push notification for incoming call
			callType, _ := data["callType"].(string)
			if callType == "" {
				callType = "voice"
			}

			// 🔧 FIX: Use display_name for FCM notification if available
			callerName := client.username
			if displayNameVal, ok := data["sender_display_name"].(string); ok && displayNameVal != "" {
				callerName = displayNameVal
			}

			sendIncomingCallNotification(recipientUID, client.uid, callerName, callType)

			// Store pending call (will be delivered when recipient comes online)
			hub.pendingCalls[recipientUID] = &PendingCall{
				callerUID:    client.uid,
				recipientUID: recipientUID,
				callData:     data,
				timestamp:    time.Now(),
			}

// 			log.Printf("✅ Stored pending call from %s to %s", client.username, recipientUID)

			// Start a goroutine to timeout after 30 seconds
			go func() {
				time.Sleep(30 * time.Second)

				// Check if call is still pending
				if pendingCall, exists := hub.pendingCalls[recipientUID]; exists {
					if pendingCall.callerUID == client.uid {
						// Call was never answered - send failure notification
						delete(hub.pendingCalls, recipientUID)

						failureMessage := map[string]interface{}{
							"type":          "call_failed",
							"reason":        "user_offline",
							"recipient_uid": recipientUID,
						}

						failureBytes, _ := json.Marshal(failureMessage)

						// Try to send to caller (if still connected)
						if callerClient, ok := hub.clients[client.uid]; ok {
							select {
							case callerClient.send <- failureBytes:
// 								log.Printf("✅ Timeout: Sent call_failed to %s after 30s", client.username)
							default:
								log.Printf("❌ Timeout: Failed to send call_failed to %s", client.username)
							}
						}

						// Log as missed
						logCallEvent(client.db, "call_missed", client.uid, recipientUID, data)
// 						log.Printf("⏱️ Pending call timeout: %s -> %s", client.username, recipientUID)
					}
				}
			}()

			return // Don't send call_offer yet, waiting for recipient to come online
		}
	}

	// 🔧 FIX: Buffer ICE candidates for pending calls (offline recipients)
	if msgType == "ice_candidate" {
		// Check if recipient has a pending call (they're offline)
		if pendingCall, exists := hub.pendingCalls[recipientUID]; exists {
			// Recipient is offline, buffer this ICE candidate
			log.Printf("📦 Buffering ice_candidate for offline recipient %s (count: %d)", recipientUID, len(pendingCall.iceCandidates)+1)
			pendingCall.iceCandidates = append(pendingCall.iceCandidates, data)
			return // Don't try to send yet - will be delivered on reconnect
		}
		// If recipient is online, forward immediately (fall through to broadcastToUser)
	}

	// Handle call cancellation/rejection - remove pending calls
	if msgType == "call_ended" || msgType == "call_rejected" {
		// Check if there's a pending call and remove it
		if pendingCall, exists := hub.pendingCalls[recipientUID]; exists {
			if pendingCall.callerUID == client.uid {
				delete(hub.pendingCalls, recipientUID)
				log.Printf("🚫 Removed pending call from %s to %s (call %s)", client.username, recipientUID, msgType)
			}
		}
	}

	// Log call metadata to database
	logCallEvent(client.db, msgType, client.uid, recipientUID, data)

	// Log call signaling
// 	log.Printf("Call signaling: %s from %s to %s", msgType, client.username, recipientUID)

	// Forward to recipient
	broadcastToUser(hub, recipientUID, data)
}

// logCallEvent logs call metadata to database for abuse prevention and debugging
func logCallEvent(db *sql.DB, eventType string, callerUID string, receiverUID string, data map[string]interface{}) {
	switch eventType {
	case "call_missed":
		// Log missed call (when recipient is offline)
		callType, _ := data["callType"].(string)
		conversationID, _ := data["conversation_id"].(float64)

		if callType == "" {
			callType = "voice"
		}

		query := `
			INSERT INTO call_logs (caller_uid, receiver_uid, call_type, call_status, conversation_id, started_at, ended_at)
			VALUES ($1, $2, $3, 'missed', $4, NOW(), NOW())
		`
		_, err := db.Exec(query, callerUID, receiverUID, callType, int(conversationID))
		if err != nil {
			log.Printf("❌ Failed to log call_missed: %v", err)
		} else {
			log.Printf("📝 Logged call_missed: %s -> %s (%s)", callerUID, receiverUID, callType)
		}

	case "call_offer":
		// Extract call type and conversation ID
		callType, _ := data["callType"].(string)
		conversationID, _ := data["conversation_id"].(float64) // JSON numbers are float64

		if callType == "" {
			callType = "voice" // default
		}

		// Create new call log entry
		query := `
			INSERT INTO call_logs (caller_uid, receiver_uid, call_type, call_status, conversation_id, started_at)
			VALUES ($1, $2, $3, 'initiated', $4, NOW())
		`
		_, err := db.Exec(query, callerUID, receiverUID, callType, int(conversationID))
		if err != nil {
			log.Printf("❌ Failed to log call_offer: %v", err)
		} else {
			log.Printf("📝 Logged call_offer: %s -> %s (%s)", callerUID, receiverUID, callType)
		}

	case "call_answer":
		// Update call status to connected
		query := `
			UPDATE call_logs
			SET call_status = 'connected'
			WHERE id = (
				SELECT id FROM call_logs
				WHERE caller_uid = $1 AND receiver_uid = $2 AND call_status = 'initiated'
				ORDER BY started_at DESC
				LIMIT 1
			)
		`
		result, err := db.Exec(query, receiverUID, callerUID) // Note: reversed for answer
		if err != nil {
			log.Printf("❌ Failed to update call_answer: %v", err)
		} else {
			rows, _ := result.RowsAffected()
			if rows > 0 {
				log.Printf("📝 Updated call to 'connected': %s <-> %s", callerUID, receiverUID)
			}
		}

	case "call_rejected":
		// Update call status to rejected
		query := `
			UPDATE call_logs
			SET call_status = 'rejected', ended_at = NOW()
			WHERE id = (
				SELECT id FROM call_logs
				WHERE caller_uid = $1 AND receiver_uid = $2 AND call_status = 'initiated'
				ORDER BY started_at DESC
				LIMIT 1
			)
		`
		result, err := db.Exec(query, receiverUID, callerUID) // Note: reversed for rejection
		if err != nil {
			log.Printf("❌ Failed to update call_rejected: %v", err)
		} else {
			rows, _ := result.RowsAffected()
			if rows > 0 {
				log.Printf("📝 Updated call to 'rejected': %s -> %s", callerUID, receiverUID)
			}
		}

	case "call_ended":
		// Update call status to completed and calculate duration
		query := `
			UPDATE call_logs
			SET call_status = 'completed',
			    ended_at = NOW(),
			    duration_seconds = EXTRACT(EPOCH FROM (NOW() - started_at))::INT
			WHERE id = (
				SELECT id FROM call_logs
				WHERE (caller_uid = $1 AND receiver_uid = $2 OR caller_uid = $2 AND receiver_uid = $1)
				  AND call_status IN ('initiated', 'connected')
				ORDER BY started_at DESC
				LIMIT 1
			)
		`
		result, err := db.Exec(query, callerUID, receiverUID)
		if err != nil {
			log.Printf("❌ Failed to update call_ended: %v", err)
		} else {
			rows, _ := result.RowsAffected()
			if rows > 0 {
				log.Printf("📝 Updated call to 'completed': %s <-> %s", callerUID, receiverUID)
			}
		}
	}
}

func handleStatusRequest(client *Client, data map[string]interface{}) {
    //log.Printf("DEBUG: Status request received from %s", client.username)

    messageIDFloat, ok := data["message_id"].(float64)
    if !ok {
        log.Printf("Invalid message_id in status request")
        return
    }
    messageID := int(messageIDFloat)
    
    //log.Printf("DEBUG: Checking status for message %d", messageID)
    
    // Query current message status from database
    var status string
    err := db.QueryRow(`
        SELECT 
            CASE 
                WHEN ms.read_at IS NOT NULL THEN 'read'
                WHEN ms.delivered_at IS NOT NULL THEN 'delivered'
                ELSE 'sent'
            END as status
        FROM message_status ms 
        WHERE ms.message_id = $1 
        LIMIT 1
    `, messageID).Scan(&status)
    
    if err != nil {
        log.Printf("Error getting message status for message %d: %v", messageID, err)
        return
    }
    
//    log.Printf("DEBUG: Message %d status is: %s", messageID, status)
    
    // Create status response
    statusResponse := map[string]interface{}{
        "type":            "message_status",
        "message_id":      messageID,
        "status":          status,
        "conversation_id": data["conversation_id"],
    }
    
    // Convert to JSON bytes
    responseBytes, err := json.Marshal(statusResponse)
    if err != nil {
        log.Printf("Error marshaling status response: %v", err)
        return
    }
    
    //log.Printf("DEBUG: Sending status response: %s", string(responseBytes))
    
    // Send to client
    select {
    case client.send <- responseBytes:
//         log.Printf("✅ Sent status update: message %d is %s", messageID, status)
    default:
        log.Printf("❌ Client send channel full, dropping status response")
        close(client.send)
    }
}

// Helper function to send push notification from WebSocket message
func sendNewMessageNotificationFromMessage(recipientUID string, message map[string]interface{}) {
	// Extract message details from WebSocket message
	senderUsername, _ := message["sender_username"].(string)
	if senderUsername == "" {
		senderUsername = "New Message"
	}
	
	// Extract sender UID from the message
	senderUID, _ := message["sender_uid"].(string)
	if senderUID == "" {
		log.Printf("Warning: No sender_uid in message for notification")
		return // Can't send notification without sender UID for quick reply
	}
	
	contentB64, _ := message["content_b64"].(string)
	messageContent := "You have a new message"
	
	// Extract conversation, message, and device IDs
	var conversationID int
	var messageID int
	var senderDeviceID int
	
	if convID, ok := message["conversation_id"]; ok {
		switch v := convID.(type) {
		case int:
			conversationID = v
		case float64:
			conversationID = int(v)
		}
	}
	
	if msgID, ok := message["message_id"]; ok {
		switch v := msgID.(type) {
		case int:
			messageID = v
		case float64:
			messageID = int(v)
		}
	}

	if devID, ok := message["sender_device_id"]; ok {
		switch v := devID.(type) {
		case int:
			senderDeviceID = v
		case float64:
			senderDeviceID = int(v)
		}
	}

	messageType, _ := message["message_type"].(string)
	if messageType == "" {
		messageType = "chat"
	}

	isGroup, _ := message["is_group"].(bool)
	
	// Send the push notification with full E2EE ciphertext and metadata
	sendNewMessageNotification(recipientUID, senderUID, senderUsername, messageContent, conversationID, messageID, contentB64, senderDeviceID, messageType, isGroup)
}

// Queue deletion notification for offline user
func queueDeletionForOfflineUser(userUID string, deleteNotification map[string]interface{}) {
// 	log.Printf("Queuing deletion notification for offline user %s", userUID)

	var messageID int
	switch v := deleteNotification["message_id"].(type) {
	case int:
		messageID = v
	case int64:
		messageID = int(v)
	case float64:
		messageID = int(v)
	default:
		log.Printf("Invalid message_id type: %T, value: %v", v, v)
		return
	}

	var conversationID int
	switch v := deleteNotification["conversation_id"].(type) {
	case int:
		conversationID = v
	case int64:
		conversationID = int(v)
	case float64:
		conversationID = int(v)
	default:
		log.Printf("Invalid conversation_id type: %T, value: %v", v, v)
		return
	}

	// deletionType, _ := deleteNotification["deletion_type"].(string) // Only used in commented log
	deletedBy, _ := deleteNotification["deleted_by"].(string)

	// Store in offline_message_queue table
	query := `
		INSERT INTO offline_message_queue (recipient_uid, sender_uid, conversation_id, message_id, message_type, message_data, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, NOW())
	`

	messageData, err := json.Marshal(deleteNotification)
	if err != nil {
		log.Printf("Failed to marshal deletion notification: %v", err)
		return
	}

	_, err = db.Exec(query, userUID, deletedBy, conversationID, messageID, "message_deleted", messageData)
	if err != nil {
		log.Printf("Failed to queue deletion for offline user %s: %v", userUID, err)
	} else {
// 		log.Printf("Successfully queued deletion (msg:%d, conv:%d, type:%s) for offline user %s",
// 			messageID, conversationID, deletionType, userUID)
	}
}

// Queue attachment notification for offline user
func queueAttachmentNotificationForOfflineUser(userUID string, attachmentNotification map[string]interface{}) {
// 	log.Printf("Queuing attachment notification for offline user %s", userUID)

	// Extract required fields with type handling
	var messageID int
	switch v := attachmentNotification["message_id"].(type) {
	case int:
		messageID = v
	case float64:
		messageID = int(v)
	default:
		log.Printf("Invalid message_id type: %T", v)
		return
	}

	var conversationID int
	switch v := attachmentNotification["conversation_id"].(type) {
	case int:
		conversationID = v
	case float64:
		conversationID = int(v)
	default:
		log.Printf("Invalid conversation_id type: %T", v)
		return
	}

	uploadedBy, _ := attachmentNotification["uploaded_by"].(string)

	query := `
		INSERT INTO offline_message_queue (recipient_uid, sender_uid, conversation_id, message_id, message_type, message_data, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, NOW())
	`

	messageData, err := json.Marshal(attachmentNotification)
	if err != nil {
		log.Printf("Failed to marshal attachment notification: %v", err)
		return
	}

	_, err = db.Exec(query, userUID, uploadedBy, conversationID, messageID, "attachment_uploaded", messageData)
	if err != nil {
		log.Printf("Failed to queue attachment notification for offline user %s: %v", userUID, err)
	} else {
// 		log.Printf("Successfully queued attachment notification (msg:%d, conv:%d) for offline user %s",
// 			messageID, conversationID, userUID)
	}
}

// Queue status update for offline user
func queueStatusUpdateForOfflineUser(userUID string, statusUpdate map[string]interface{}) {
	//log.Printf("DEBUG: Queuing status update data: %+v", statusUpdate)
	
	// Handle both int and float64 types for message_id
	var messageID int
	switch v := statusUpdate["message_id"].(type) {
	case int:
		messageID = v
	case float64:
		messageID = int(v)
	default:
		log.Printf("Invalid message_id type: %T, value: %v", v, v)
		return
	}
	
	status, ok := statusUpdate["status"].(string)
	if !ok {
		log.Printf("Invalid status type: %T, value: %v", statusUpdate["status"], statusUpdate["status"])
		return
	}
	
	// Handle both int and float64 types for conversation_id
	var conversationID int
	switch v := statusUpdate["conversation_id"].(type) {
	case int:
		conversationID = v
	case float64:
		conversationID = int(v)
	default:
		log.Printf("Invalid conversation_id type: %T, value: %v", v, v)
		return
	}
	
	if messageID == 0 || status == "" || conversationID == 0 {
		log.Printf("Invalid status update values: messageID=%d, status='%s', conversationID=%d", messageID, status, conversationID)
		return
	}
	
	// Store in database for later delivery
	query := `
		INSERT INTO pending_status_updates (user_uid, message_id, status, conversation_id, created_at)
		VALUES ($1, $2, $3, $4, NOW())
		ON CONFLICT (user_uid, message_id, status) DO NOTHING
	`
	
	_, err := db.Exec(query, userUID, messageID, status, conversationID)
	if err != nil {
		log.Printf("Failed to queue status update: %v", err)
	} else {
// 		log.Printf("Successfully queued status update %s for message %d for offline user %s", status, messageID, userUID)
	}
}

// Send pending status updates when user connects
func sendPendingStatusUpdates(client *Client) {
	query := `
		SELECT message_id, status, conversation_id 
		FROM pending_status_updates 
		WHERE user_uid = $1 
		ORDER BY created_at ASC
	`
	
	rows, err := db.Query(query, client.uid)
	if err != nil {
		log.Printf("Failed to fetch pending status updates for %s: %v", client.uid, err)
		return
	}
	defer rows.Close()
	
	var sentCount int
	for rows.Next() {
		var messageID, conversationID int
		var status string
		
		if err := rows.Scan(&messageID, &status, &conversationID); err != nil {
			continue
		}
		
		statusUpdate := map[string]interface{}{
			"type":            "message_status",
			"message_id":      messageID,
			"status":          status,
			"conversation_id": conversationID,
		}
		
		messageBytes, _ := json.Marshal(statusUpdate)
		select {
		case client.send <- messageBytes:
			sentCount++
		default:
			log.Printf("Failed to send pending status update to %s", client.username)
		}
	}
	
	if sentCount > 0 {
// 		log.Printf("Sent %d pending status updates to %s", sentCount, client.username)
		
		// Clear sent updates
		_, err = db.Exec("DELETE FROM pending_status_updates WHERE user_uid = $1", client.uid)
		if err != nil {
			log.Printf("Failed to clear pending status updates for %s: %v", client.uid, err)
		}
	}
}

func (c *Client) readPump() {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()

	c.conn.SetReadLimit(maxMessageSize)
	c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("WebSocket read error for client '%s': %v", c.username, err)
			}
			break
		}

		 //log.Printf("DEBUG: Raw message received from %s: %s", c.username, string(message))

		// Parse the message to check its type
		var msgData map[string]interface{}
		if err := json.Unmarshal(message, &msgData); err != nil {
			log.Printf("SECURITY WARNING: Rejecting non-JSON message from %s: %v", c.username, err)

			errorResponse := map[string]interface{}{
				"type":  "error",
				"error": "Message must be valid JSON",
			}
			errorBytes, _ := json.Marshal(errorResponse)
			select {
			case c.send <- errorBytes:
			default:
				log.Printf("Failed to send error response to %s", c.username)
			}
			continue
		}

		msgType, ok := msgData["type"].(string)
		if !ok {
			// SECURITY: Reject messages without type field
			log.Printf("SECURITY WARNING: Rejecting message without type field from %s", c.username)

			errorResponse := map[string]interface{}{
				"type":  "error",
				"error": "Message must have a 'type' field",
			}
			errorBytes, _ := json.Marshal(errorResponse)
			select {
			case c.send <- errorBytes:
			default:
				log.Printf("Failed to send error response to %s", c.username)
			}
			continue
		}

		// Handle different message types
		switch msgType {
		case "ping":
			// Handle ping messages
			pongMessage := map[string]interface{}{
				"type": "pong",
				"timestamp": time.Now().UTC().UnixMilli(),
			}
			pongBytes, _ := json.Marshal(pongMessage)
			select {
			case c.send <- pongBytes:
				//log.Printf("Pong sent to %s", c.username)
			default:
				log.Printf("Failed to send pong to %s", c.username)
			}

		  case "message_status":
      		// Handle status updates
      		handleStatusUpdate(c, msgData, c.hub, db)

		case "typing":
			handleTypingIndicator(c.hub, c, msgData)

		case "presence_query":
			handlePresenceQuery(c, msgData)

		case "status_request":
    		handleStatusRequest(c, msgData)

		case "call_offer", "call_answer", "ice_candidate", "call_rejected", "call_ended":
			// Handle WebRTC call signaling - forward to recipient
			handleCallSignaling(c.hub, c, msgData)

		case "add_reaction":
			handleAddReaction(c, msgData, c.hub, db)

		case "remove_reaction":
			handleRemoveReaction(c, msgData, c.hub, db)

		case "session_reset_required":
			// Forward session reset notification to recipient
			handleSessionResetNotification(c.hub, c, msgData)

		default:
			// SECURITY: Reject unencrypted chat messages
			// All encrypted messages should go through REST API, not WebSocket
			log.Printf("SECURITY WARNING: Rejecting WebSocket message type '%s' from %s - use REST API for encrypted messages", msgType, c.username)

			errorResponse := map[string]interface{}{
				"type":  "error",
				"error": "Use REST API for sending messages. WebSocket is only for signaling.",
			}
			errorBytes, _ := json.Marshal(errorResponse)
			select {
			case c.send <- errorBytes:
				log.Printf("Sent error response to %s", c.username)
			default:
				log.Printf("Failed to send error response to %s", c.username)
			}
		}
	}
}

func (c *Client) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				// channel closed
				_ = c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			if err := c.conn.WriteMessage(websocket.TextMessage, message); err != nil {
				log.Printf("WebSocket write error for client '%s': %v", c.username, err)
				return
			}
		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				log.Printf("WebSocket ping error for client '%s': %v", c.username, err)
				return
			}
		}
	}
}

// areFriends checks if two users have an accepted friendship.
// user_a_uid must be lexicographically ≤ user_b_uid per schema constraint.
func areFriends(uid1, uid2 string) bool {
	userA, userB := uid1, uid2
	if userA > userB {
		userA, userB = userB, userA
	}
	var exists bool
	db.QueryRow(`SELECT EXISTS(SELECT 1 FROM friendships WHERE user_a_uid=$1 AND user_b_uid=$2 AND status='accepted')`, userA, userB).Scan(&exists)
	return exists
}

func handlePresenceQuery(client *Client, queryData map[string]interface{}) {
	targetUID, ok := queryData["target_uid"].(string)
	if !ok {
		log.Printf("Invalid target_uid in presence query")
		return
	}

	log.Printf("Presence query from %s for user %s", client.username, targetUID)

	// Check if user is currently online
	globalHub.mu.RLock()
	_, isOnline := globalHub.clients[targetUID]
	globalHub.mu.RUnlock()

	var lastSeen time.Time
	if !isOnline {
		// Get last_seen from database
		err := db.QueryRow(`
			SELECT last_seen_at
			FROM devices
			WHERE firebase_uid = $1
			ORDER BY last_seen_at DESC
			LIMIT 1
		`, targetUID).Scan(&lastSeen)
		if err != nil {
			log.Printf("Error fetching last_seen for %s: %v", targetUID, err)
			lastSeen = time.Now().UTC()
		}
	} else {
		lastSeen = time.Now().UTC()
	}

	// Check last_seen_privacy of the target user before responding
	var lsPrivacy string
	if err := db.QueryRow("SELECT COALESCE(last_seen_privacy, 'everyone') FROM profiles WHERE firebase_uid = $1", targetUID).Scan(&lsPrivacy); err != nil {
		lsPrivacy = "everyone"
	}

	canSeePresence := false
	switch lsPrivacy {
	case "everyone":
		canSeePresence = true
	case "friends":
		canSeePresence = areFriends(client.uid, targetUID)
	case "nobody":
		canSeePresence = false
	}

	if !canSeePresence {
		// Return a hidden response — user appears offline with no last_seen
		hiddenResponse := map[string]interface{}{
			"type":      "presence_status",
			"user_uid":  targetUID,
			"is_online": false,
			"last_seen": nil,
			"hidden":    true,
		}
		hiddenJSON, err := json.Marshal(hiddenResponse)
		if err != nil {
			return
		}
		select {
		case client.send <- hiddenJSON:
		default:
			log.Printf("Failed to send hidden presence response to %s (buffer full)", client.username)
		}
		return
	}

	// Send presence response
	response := map[string]interface{}{
		"type":      "presence_status",
		"user_uid":  targetUID,
		"is_online": isOnline,
		"last_seen": lastSeen.Unix(),
	}

	responseJSON, err := json.Marshal(response)
	if err != nil {
		log.Printf("Error marshaling presence response: %v", err)
		return
	}

	select {
	case client.send <- responseJSON:
// 		log.Printf("Sent presence response to %s: online=%v", client.username, isOnline)
	default:
		log.Printf("Failed to send presence response to %s (buffer full)", client.username)
	}
}

func handleTypingIndicator(hub *Hub, client *Client, typingData map[string]interface{}) {
	conversationId, ok := typingData["conversation_id"].(float64)
	if !ok {
		log.Printf("Invalid conversation_id in typing indicator")
		return
	}

	isTyping, ok := typingData["is_typing"].(bool)
	if !ok {
		log.Printf("Invalid is_typing in typing indicator")
		return
	}

	log.Printf("Typing indicator from %s in conversation %d: %v", client.username, int(conversationId), isTyping)

	// Get all members of this conversation
	rows, err := db.Query(`
		SELECT profile_uid
		FROM conversation_members
		WHERE conversation_id = $1 AND profile_uid != $2
	`, int(conversationId), client.uid)
	if err != nil {
		log.Printf("Error fetching conversation members: %v", err)
		return
	}
	defer rows.Close()

	// Prepare the typing notification
	notification := map[string]interface{}{
		"type":            "typing",
		"conversation_id": int(conversationId),
		"sender_uid":      client.uid,
		"sender_username": client.username,
		"is_typing":       isTyping,
	}

	notificationJSON, err := json.Marshal(notification)
	if err != nil {
		log.Printf("Error marshaling typing notification: %v", err)
		return
	}

	// Send to all other members in the conversation
	for rows.Next() {
		var memberUID string
		if err := rows.Scan(&memberUID); err != nil {
			continue
		}

		hub.mu.RLock()
		if recipientClient, exists := hub.clients[memberUID]; exists {
			select {
			case recipientClient.send <- notificationJSON:
// 				log.Printf("Sent typing indicator to %s", memberUID)
			default:
				log.Printf("Failed to send typing indicator to %s (buffer full)", memberUID)
			}
		}
		hub.mu.RUnlock()
	}
}

func handleStatusUpdate(client *Client, statusData map[string]interface{}, hub *Hub, db *sql.DB) {
        messageId, ok := statusData["message_id"].(float64)
        if !ok {
                log.Printf("Invalid message_id in status update")
                return
        }

        status, ok := statusData["status"].(string)
        if !ok {
                log.Printf("Invalid status in status update")
                return
        }

        conversationId, ok := statusData["conversation_id"].(float64)
        if !ok {
                log.Printf("Invalid conversation_id in status update")
                return
        }

        // ✅ PERFORMANCE FIX: Check if we recently sent this status update
        statusKey := fmt.Sprintf("%d_%s_%s", int(messageId), client.uid, status)

        hub.statusMu.RLock()
        lastUpdate, exists := hub.recentStatusUpdates[statusKey]
        hub.statusMu.RUnlock()

        if exists && time.Since(lastUpdate) < 5*time.Second {
//                 log.Printf("⏭️ Skipping duplicate status update for message %d (%s) from %s", int(messageId), status, client.uid)

                // ✅ FIX: Still send ACK even when skipping, to stop Flutter from retrying
                ackPayload := map[string]interface{}{
                        "type":       "message_ack",
                        "message_id": int(messageId),
                }
                ackBytes, _ := json.Marshal(ackPayload)
                select {
                case client.send <- ackBytes:
//                         log.Printf("✅ ACK sent for duplicate status update (message %d)", int(messageId))
                default:
                        log.Printf("⚠️ Failed to send ACK for duplicate status update (message %d)", int(messageId))
                }
                return
        }

        // Track this status update
        hub.statusMu.Lock()
        hub.recentStatusUpdates[statusKey] = time.Now()

        // Clean up old entries (keep only last 2 minutes)
        for key, timestamp := range hub.recentStatusUpdates {
                if time.Since(timestamp) > 2*time.Minute {
                        delete(hub.recentStatusUpdates, key)
                }
        }
        hub.statusMu.Unlock()

        // Update database
        err := updateMessageStatusInDB(int(messageId), client.uid, status, db)
        if err != nil {
                log.Printf("Failed to update message status in DB: %v", err)
                return
        }

        // Get the original message sender to notify them
        senderUID, err := getMessageSender(int(messageId), db)
        if err != nil {
                log.Printf("Failed to get message sender: %v", err)
                return
        }

        // Don't send status update if recipient is the sender
        if senderUID == client.uid {
                return
        }

        statusResponse := map[string]interface{}{
                "type":            "message_status",
                "message_id":      int(messageId),
                "status":          status,
                "conversation_id": int(conversationId),
                "recipient_uid":   client.uid,
        }

        broadcastToUser(hub, senderUID, statusResponse)
//         log.Printf("✅ Broadcasted status %s for message %d to sender %s", status, int(messageId), senderUID)

        // ✅ FIX: Send ACK back to client who sent the status update
        ackPayload := map[string]interface{}{
                "type":       "message_ack",
                "message_id": int(messageId),
        }
        ackBytes, _ := json.Marshal(ackPayload)
        select {
        case client.send <- ackBytes:
//                 log.Printf("✅ ACK sent for status update (message %d)", int(messageId))
        default:
                log.Printf("⚠️ Failed to send ACK for status update (message %d)", int(messageId))
        }
  }


func updateMessageStatusInDB(messageID int, recipientUID string, status string, db *sql.DB) error {
	var query string
	var args []interface{}
	
	switch status {
	case "delivered":
		query = `
			UPDATE message_status 
			SET delivered_at = NOW() 
			WHERE message_id = $1 AND recipient_uid = $2 AND delivered_at IS NULL
		`
	case "read":
		query = `
			UPDATE message_status 
			SET read_at = NOW() 
			WHERE message_id = $1 AND recipient_uid = $2
		`
	default:
		return fmt.Errorf("unknown status: %s", status)
	}
	
	args = []interface{}{messageID, recipientUID}
	
	result, err := db.Exec(query, args...)
	if err != nil {
		return fmt.Errorf("database update failed: %v", err)
	}

	// Also mark offline_message_queue as delivered so it won't be re-delivered on reconnect
	_, _ = db.Exec(`
		UPDATE offline_message_queue 
		SET delivered = true, delivered_at = NOW() 
		WHERE message_id = $1 AND recipient_uid = $2 AND delivered = false
	`, messageID, recipientUID)
	
	rowsAffected, _ := result.RowsAffected()
	log.Printf("Updated %d message_status rows for message %d, recipient %s, status %s", 
		rowsAffected, messageID, recipientUID, status)
	
	return nil
}

// Get the sender of a message
func getMessageSender(messageID int, db *sql.DB) (string, error) {
	var senderUID string
	err := db.QueryRow(`
		SELECT sender_uid FROM messages WHERE id = $1
	`, messageID).Scan(&senderUID)
	
	if err != nil {
		return "", fmt.Errorf("failed to get sender for message %d: %v", messageID, err)
	}
	
	return senderUID, nil
}


// Broadcast presence status to all friends/conversation members
func broadcastPresenceStatus(userUID string, isOnline bool, lastSeen time.Time) {
// 	log.Printf("Broadcasting presence for %s: online=%v", userUID, isOnline)

	// Fetch the broadcasting user's last_seen_privacy once before querying recipients
	var lsPrivacy string
	if err := db.QueryRow("SELECT COALESCE(last_seen_privacy, 'everyone') FROM profiles WHERE firebase_uid = $1", userUID).Scan(&lsPrivacy); err != nil {
		lsPrivacy = "everyone"
	}
	// If nobody, skip broadcast entirely — no one should know this user's presence
	if lsPrivacy == "nobody" {
		return
	}

	// Get all users who should receive this presence update (friends + conversation members)
	query := `
		SELECT DISTINCT p.firebase_uid
		FROM profiles p
		WHERE p.firebase_uid IN (
			-- Friends
			SELECT CASE
				WHEN user_a_uid = $1 THEN user_b_uid
				ELSE user_a_uid
			END as friend_uid
			FROM friendships
			WHERE (user_a_uid = $1 OR user_b_uid = $1)
			AND status = 'accepted'

			UNION

			-- Conversation members
			SELECT profile_uid
			FROM conversation_members
			WHERE conversation_id IN (
				SELECT conversation_id
				FROM conversation_members
				WHERE profile_uid = $1
			)
			AND profile_uid != $1
		)
	`

	rows, err := db.Query(query, userUID)
	if err != nil {
		log.Printf("Error fetching recipients for presence broadcast: %v", err)
		return
	}
	defer rows.Close()

	// Prepare presence notification
	notification := map[string]interface{}{
		"type":      "presence_status",
		"user_uid":  userUID,
		"is_online": isOnline,
		"last_seen": lastSeen.Unix(),
	}

	notificationJSON, err := json.Marshal(notification)
	if err != nil {
		log.Printf("Error marshaling presence notification: %v", err)
		return
	}

	// Send to all relevant users
	sentCount := 0
	globalHub.mu.RLock()
	defer globalHub.mu.RUnlock()

	for rows.Next() {
		var recipientUID string
		if err := rows.Scan(&recipientUID); err != nil {
			continue
		}

		// Privacy filter: if 'friends', only broadcast to accepted friends (not just conversation members)
		if lsPrivacy == "friends" && !areFriends(userUID, recipientUID) {
			continue
		}

		if recipientClient, exists := globalHub.clients[recipientUID]; exists {
			select {
			case recipientClient.send <- notificationJSON:
				sentCount++
			default:
				log.Printf("Failed to send presence to %s (buffer full)", recipientUID)
			}
		}
	}

// 	log.Printf("Sent presence notification to %d users", sentCount)
}

func (h *Hub) run() {
	broadcastUserList := func() {
		var usernames []string
		for u := range h.clients {
			usernames = append(usernames, u)
		}
		userListBytes, err := json.Marshal(map[string]interface{}{
			"type":  "user_list_update",
			"users": usernames,
		})
		if err != nil {
			log.Printf("Error marshalling user list: %v", err)
			return
		}
		for _, client := range h.clients {
			select {
			case client.send <- userListBytes:
			default:
				close(client.send)
				delete(h.clients, client.username)
			}
		}
	}

	for {
		select {
		case client := <-h.register:
			h.clients[client.uid] = client
			log.Printf("Client '%s' (UID: %s) registered. Total clients: %d", client.username, client.uid, len(h.clients))

			// Broadcast online status to friends
			broadcastPresenceStatus(client.uid, true, time.Now().UTC())

			sendPendingStatusUpdates(client)

			// Deliver offline messages (including quick replies sent while offline)
			deliverOfflineMessages(client)

			// Check for pending call offers
			if pendingCall, exists := h.pendingCalls[client.uid]; exists {
				log.Printf("📞 Delivering pending call + %d buffered ICE candidates from %s to %s", len(pendingCall.iceCandidates), pendingCall.callerUID, client.username)

				// Deliver the call offer to the now-online recipient
				callBytes, err := json.Marshal(pendingCall.callData)
				if err == nil {
					select {
					case client.send <- callBytes:
						log.Printf("✅ Delivered pending call_offer to %s", client.username)
					default:
						log.Printf("❌ Failed to deliver pending call_offer to %s", client.username)
					}
				}

				// 🔧 FIX: Deliver all buffered ICE candidates
				for i, iceCandidate := range pendingCall.iceCandidates {
					iceBytes, err := json.Marshal(iceCandidate)
					if err == nil {
						select {
						case client.send <- iceBytes:
							log.Printf("✅ Delivered buffered ice_candidate %d/%d to %s", i+1, len(pendingCall.iceCandidates), client.username)
						default:
							log.Printf("❌ Failed to deliver buffered ice_candidate %d to %s", i+1, client.username)
						}
					}
				}

				// Remove from pending calls
				delete(h.pendingCalls, client.uid)
			}

			broadcastUserList()

		case client := <-h.unregister:
			if _, ok := h.clients[client.uid]; ok {
				delete(h.clients, client.uid)
				close(client.send)
				log.Printf("Client '%s' unregistered. Total clients: %d", client.username, len(h.clients))

				// Update last_seen_at in database
				_, err := db.Exec(`
					UPDATE devices
					SET last_seen_at = $1
					WHERE firebase_uid = $2
				`, time.Now().UTC(), client.uid)
				if err != nil {
					log.Printf("Error updating last_seen for %s: %v", client.uid, err)
				}

				// Broadcast offline status to friends
				broadcastPresenceStatus(client.uid, false, time.Now().UTC())
				broadcastUserList()
			}

		case usernameUpdate := <-h.updateUsername:
			oldUsername := usernameUpdate["oldUsername"]
			newUsername := usernameUpdate["newUsername"]
			if client, ok := h.clients[oldUsername]; ok {
				delete(h.clients, oldUsername)
				client.username = newUsername
				h.clients[newUsername] = client
				log.Printf("Hub updated username from '%s' to '%s'", oldUsername, newUsername)
				broadcastUserList()
			}

		case hubMsg := <-h.broadcast:
			messageBytes := hubMsg.message
			sender := hubMsg.sender

			// Targeted messages or server-initiated broadcasts
			if hubMsg.recipients != nil || sender == nil {
				if hubMsg.recipients != nil {
					log.Printf("Broadcasting targeted message to %d recipients: %v", len(hubMsg.recipients), hubMsg.recipients)
					log.Printf("Current connected clients: %v", func() []string {
						uids := []string{}
						for uid := range h.clients {
							uids = append(uids, uid)
						}
						return uids
					}())
					for _, recipientUID := range hubMsg.recipients {
						if client, ok := h.clients[recipientUID]; ok {
// 							log.Printf("✅ Sending to client UID: %s (username: %s)", recipientUID, client.username)
							select {
							case client.send <- messageBytes:
							default:
								close(client.send)
								delete(h.clients, client.uid)
							}
						} else {
							log.Printf("❌ Client not found for UID: %s", recipientUID)
						}
					}
				} else {
					// server-wide broadcast
					log.Printf("Broadcasting server-wide message to all %d clients", len(h.clients))
					for _, client := range h.clients {
						select {
						case client.send <- messageBytes:
						default:
							close(client.send)
							delete(h.clients, client.username)
						}
					}
				}
				continue
			}

			// Standard chat message from a connected user.
			var incomingMsg IncomingChatMessage
			if err := json.Unmarshal(messageBytes, &incomingMsg); err != nil {
				log.Printf("Received unrecognized WebSocket message from '%s': %s", sender.username, string(messageBytes))
				continue
			}

			conversationID := incomingMsg.ConversationID

			// Build message to save and broadcast - SIMPLIFIED
			var newMsg Message
			newMsg.Content = incomingMsg.Content
			newMsg.Username = sender.username
			newMsg.SenderUID = sender.uid

			// FIXED: Insert into DB matching your actual schema
			sqlStatement := `
				INSERT INTO messages (conversation_id, sender_uid, content, sender_device_id, status, message_type, reply_to_message_id)
				VALUES ($1, $2, $3, $4, $5, $6, $7)
				RETURNING id, created_at
			`

			var returnedID int
			var createdAt time.Time

			// Convert string content to bytes for BYTEA column
			contentBytes := []byte(newMsg.Content)

			// Determine sender device ID:
			// 1) From incoming message if provided
			senderDeviceID := incomingMsg.SenderDeviceID
			if senderDeviceID <= 0 {
				// 2) Fallback to sender's registered device in DB
				err := h.db.QueryRow("SELECT device_id FROM devices WHERE firebase_uid = $1 ORDER BY last_seen_at DESC NULLS LAST LIMIT 1", sender.uid).Scan(&senderDeviceID)
				if err != nil || senderDeviceID <= 0 {
					senderDeviceID = 1
				}
			}

			err := h.db.QueryRow(
				sqlStatement,
				conversationID,
				sender.uid,
				contentBytes,           // BYTEA content
				senderDeviceID,        // sender_device_id
				"sent",               // status
				"chat",               // message_type
				newMsg.ReplyToMessageID, // reply_to_message_id (can be nil)
			).Scan(&returnedID, &createdAt)

			if err != nil {
				log.Printf("Error saving message to DB for conversation %d from %s: %v", conversationID, sender.username, err)
				continue
			}

			newMsg.ID = returnedID
			newMsg.Timestamp = createdAt

			ackPayload := map[string]interface{}{
    			"type":       "message_ack", 
    			"message_id": returnedID,
			}
			ackBytes, _ := json.Marshal(ackPayload)
			select {
				case sender.send <- ackBytes:
//     			log.Printf("ACK sent for message %d", returnedID)
				default:
    				log.Printf("Failed to send ACK")
			}		

			// Fetch conversation member UIDs to broadcast to
			rows, err := h.db.Query(`
				SELECT cm.profile_uid
				FROM conversation_members cm
				WHERE cm.conversation_id = $1
			`, conversationID)
			if err != nil {
				log.Printf("Error finding members for broadcast (conv %d): %v", conversationID, err)
				continue
			}
			var memberUIDs []string
			for rows.Next() {
				var uid string
				if err := rows.Scan(&uid); err != nil {
					continue
				}
				memberUIDs = append(memberUIDs, uid)
			}
			rows.Close()

			// Query if conversation is a group
			var isGroup bool
			err = h.db.QueryRow("SELECT is_group FROM conversations WHERE id = $1", conversationID).Scan(&isGroup)
			if err != nil {
				log.Printf("Failed to query is_group for conversation %d: %v", conversationID, err)
				isGroup = false // Default to false if query fails
			}
// 			log.Printf("DEBUG HUB: Conversation %d, is_group: %v", conversationID, isGroup)

			// Build payload with correct format for Flutter WebSocketService
			broadcastPayload := map[string]interface{}{
				"type":             "new_message",
				"message_id":       returnedID,
				"conversation_id":  conversationID,
				"sender_uid":       sender.uid,
				"sender_username":  sender.username,
				"content_b64":      base64.StdEncoding.EncodeToString([]byte(newMsg.Content)),
				"created_at":       createdAt.UTC().Format(time.RFC3339),
				"sender_device_id": senderDeviceID,
				"message_type":     "chat",
				"is_group":         isGroup,
			}

			// Add reply_to_message_id if present
			if newMsg.ReplyToMessageID != nil {
				broadcastPayload["reply_to_message_id"] = *newMsg.ReplyToMessageID
			}
// 			log.Printf("DEBUG HUB: broadcastPayload created with is_group: %v", broadcastPayload["is_group"])

			// Broadcast to each member by UID
			clientList := make([]string, 0, len(h.clients))
			clientUIDs := make([]string, 0, len(h.clients))
			for uname, c := range h.clients {
				clientList = append(clientList, uname)
				clientUIDs = append(clientUIDs, c.uid)
			}	
			log.Printf("About to broadcast - hub currently has %d clients. usernames=%v, uids=%v",
	len(h.clients), clientList, clientUIDs)
			log.Printf("Broadcasting message %d to %d recipients", returnedID, len(memberUIDs))
			for _, uid := range memberUIDs {
				broadcastToUser(h, uid, broadcastPayload)
			}
		}
	}
}
// Handle adding a reaction to a message
func handleAddReaction(c *Client, msgData map[string]interface{}, hub *Hub, db *sql.DB) {
	messageID, ok := msgData["message_id"].(float64)
	if !ok {
		log.Printf("Invalid message_id in add_reaction from %s", c.username)
		return
	}

	emoji, ok := msgData["emoji"].(string)
	if !ok || emoji == "" {
		log.Printf("Invalid emoji in add_reaction from %s", c.username)
		return
	}

	// Insert reaction into database (ON CONFLICT DO NOTHING handles duplicates)
	_, err := db.Exec(`
		INSERT INTO message_reactions (message_id, user_uid, emoji)
		VALUES ($1, $2, $3)
		ON CONFLICT (message_id, user_uid, emoji) DO NOTHING
	`, int(messageID), c.uid, emoji)

	if err != nil {
		log.Printf("Error inserting reaction: %v", err)
		return
	}

	// Get conversation_id for this message to broadcast to members
	var conversationID int
	err = db.QueryRow("SELECT conversation_id FROM messages WHERE id = $1", int(messageID)).Scan(&conversationID)
	if err != nil {
		log.Printf("Error getting conversation_id for message %d: %v", int(messageID), err)
		return
	}

	// Get conversation members
	rows, err := db.Query(`
		SELECT profile_uid FROM conversation_members WHERE conversation_id = $1
	`, conversationID)
	if err != nil {
		log.Printf("Error finding members for reaction broadcast: %v", err)
		return
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

	// Broadcast reaction_added to all conversation members
	payload := map[string]interface{}{
		"type":       "reaction_added",
		"message_id": int(messageID),
		"user_uid":   c.uid,
		"username":   c.username,
		"emoji":      emoji,
	}

	for _, uid := range memberUIDs {
		broadcastToUser(hub, uid, payload)
	}

	log.Printf("Reaction %s added by %s to message %d", emoji, c.username, int(messageID))
}

// Handle removing a reaction from a message
func handleRemoveReaction(c *Client, msgData map[string]interface{}, hub *Hub, db *sql.DB) {
	messageID, ok := msgData["message_id"].(float64)
	if !ok {
		log.Printf("Invalid message_id in remove_reaction from %s", c.username)
		return
	}

	emoji, ok := msgData["emoji"].(string)
	if !ok || emoji == "" {
		log.Printf("Invalid emoji in remove_reaction from %s", c.username)
		return
	}

	// Delete reaction from database
	result, err := db.Exec(`
		DELETE FROM message_reactions 
		WHERE message_id = $1 AND user_uid = $2 AND emoji = $3
	`, int(messageID), c.uid, emoji)

	if err != nil {
		log.Printf("Error deleting reaction: %v", err)
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		log.Printf("No reaction found to remove for message %d, user %s, emoji %s", int(messageID), c.username, emoji)
		return
	}

	// Get conversation_id for this message to broadcast to members
	var conversationID int
	err = db.QueryRow("SELECT conversation_id FROM messages WHERE id = $1", int(messageID)).Scan(&conversationID)
	if err != nil {
		log.Printf("Error getting conversation_id for message %d: %v", int(messageID), err)
		return
	}

	// Get conversation members
	rows, err := db.Query(`
		SELECT profile_uid FROM conversation_members WHERE conversation_id = $1
	`, conversationID)
	if err != nil {
		log.Printf("Error finding members for reaction broadcast: %v", err)
		return
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

	// Broadcast reaction_removed to all conversation members
	payload := map[string]interface{}{
		"type":       "reaction_removed",
		"message_id": int(messageID),
		"user_uid":   c.uid,
		"emoji":      emoji,
	}

	for _, uid := range memberUIDs {
		broadcastToUser(hub, uid, payload)
	}

	log.Printf("Reaction %s removed by %s from message %d", emoji, c.username, int(messageID))
}
