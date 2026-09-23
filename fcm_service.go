package main

import (
	"fmt"
	"log"


	"firebase.google.com/go/v4/messaging"
)



// Send push notification using modern Firebase Admin SDK
func sendPushNotification(fcmToken string, title string, body string, data map[string]string) error {
    if fcmClient == nil {
        return fmt.Errorf("FCM client not initialized")
    }

    // Convert data map to string values (FCM requires string values)
    stringData := make(map[string]string)
    for k, v := range data {
        stringData[k] = fmt.Sprintf("%v", v)
    }
    
    // Add title and body to data payload instead of notification
    stringData["title"] = title
    stringData["body"] = body

    message := &messaging.Message{
        Token: fcmToken,
        // Remove the Notification field entirely for data-only messages
        Data: stringData,
        Android: &messaging.AndroidConfig{
            Priority: "high",
            // Remove AndroidNotification for data-only messages
        },
        // Remove APNS config if you're only targeting Android for now
    }

    response, err := fcmClient.Send(ctx, message)
    if err != nil {
        return fmt.Errorf("failed to send FCM message: %v", err)
    }

    log.Printf("FCM message sent successfully: %s", response)
    return nil
}

// Send new message notification to offline users
func sendNewMessageNotification(recipientUID string, senderUID string, senderUsername string, messageContent string, conversationID int, messageID int, contentB64 string, senderDeviceID int, messageType string, isGroup bool, groupName string, senderAvatar string, groupAvatar string) {
	if fcmClient == nil {
		log.Printf("FCM client not initialized, skipping notification to %s", recipientUID)
		return
	}

	// Get all FCM tokens for recipient's devices (multi-device support)
	rows, err := db.Query(`
		SELECT device_id, fcm_token FROM devices 
		WHERE firebase_uid = $1 AND fcm_token IS NOT NULL AND fcm_token != ''
		ORDER BY last_seen_at DESC
	`, recipientUID)
	if err != nil {
		log.Printf("Error querying FCM tokens for user %s: %v", recipientUID, err)
		return
	}
	defer rows.Close()

	type devToken struct {
		deviceID int
		token    string
	}
	var targetDevices []devToken
	for rows.Next() {
		var dID int
		var token string
		if err := rows.Scan(&dID, &token); err == nil && token != "" {
			targetDevices = append(targetDevices, devToken{deviceID: dID, token: token})
		}
	}

	if len(targetDevices) == 0 {
		log.Printf("No active FCM tokens found for user %s", recipientUID)
		return
	}

	// Prepare notification data
	title := senderUsername
	if isGroup && groupName != "" {
		title = groupName
	}
	body := messageContent
	if body == "" {
		body = "You have a new message"
	}
	if len(body) > 100 {
		body = body[:97] + "..."
	}

	// FCM data payload (all values must be strings) - includes content_b64 for client E2EE decryption
	data := map[string]string{
		"type":             "new_message",
		"conversation_id":  fmt.Sprintf("%d", conversationID),
		"message_id":       fmt.Sprintf("%d", messageID),
		"sender_username":  senderUsername,
		"sender_uid":       senderUID,
		"recipient_uid":    recipientUID,
		"content_b64":      contentB64,
		"sender_device_id": fmt.Sprintf("%d", senderDeviceID),
		"msg_type":         messageType,
		"is_group":         fmt.Sprintf("%t", isGroup),
		"group_name":       groupName,
		"sender_avatar":    senderAvatar,
		"group_avatar":     groupAvatar,
		"click_action":     "FLUTTER_NOTIFICATION_CLICK",
	}

	sentAtLeastOnce := false
	for _, dev := range targetDevices {
		if err := sendPushNotification(dev.token, title, body, data); err != nil {
			log.Printf("Failed to send push notification to %s (device %d): %v", recipientUID, dev.deviceID, err)
			if messaging.IsRegistrationTokenNotRegistered(err) {
				log.Printf("FCM token unregistered for user %s device %d, clearing...", recipientUID, dev.deviceID)
				db.Exec(`UPDATE devices SET fcm_token = NULL WHERE firebase_uid = $1 AND device_id = $2`, recipientUID, dev.deviceID)
			}
		} else {
			sentAtLeastOnce = true
			log.Printf("Push notification sent to %s (device %d) for message %d", recipientUID, dev.deviceID, messageID)
		}
	}

	if sentAtLeastOnce {
		// Mark message as delivered since notification was sent successfully
		_, err := db.Exec(`
			UPDATE message_status 
			SET delivered_at = NOW() 
			WHERE message_id = $1 AND recipient_uid = $2 AND delivered_at IS NULL
		`, messageID, recipientUID)

		if err != nil {
			log.Printf("Failed to update delivered status for message %d: %v", messageID, err)
		} else {
			log.Printf("Message %d marked as delivered for user %s", messageID, recipientUID)

			// Broadcast delivered status to sender
			statusMessage := map[string]interface{}{
				"type":            "message_status",
				"message_id":      messageID,
				"status":          "delivered",
				"conversation_id": conversationID,
			}
			broadcastToUser(globalHub, senderUID, statusMessage)
		}
	}
}


// Send incoming call notification to offline user
func sendIncomingCallNotification(recipientUID string, callerUID string, callerName string, callType string) {
	// Get FCM token for recipient
	var fcmToken string
	err := db.QueryRow(`
		SELECT fcm_token FROM devices
		WHERE firebase_uid = $1 AND fcm_token IS NOT NULL AND fcm_token != ''
		ORDER BY last_seen_at DESC LIMIT 1
	`, recipientUID).Scan(&fcmToken)

	if err != nil {
		log.Printf("No FCM token found for user %s: %v", recipientUID, err)
		return
	}

	// Prepare notification
	title := fmt.Sprintf("Incoming %s call", callType)
	body := fmt.Sprintf("%s is calling you", callerName)

	// FCM data payload
	data := map[string]string{
		"type":         "incoming_call",
		"caller_uid":   callerUID,
		"caller_name":  callerName,
		"call_type":    callType,
		"click_action": "FLUTTER_NOTIFICATION_CLICK",
	}

	// Send the notification
	if err := sendPushNotification(fcmToken, title, body, data); err != nil {
		log.Printf("Failed to send call notification to %s: %v", recipientUID, err)
	} else {
		log.Printf("📞 Call notification sent to %s (from %s)", recipientUID, callerName)
	}
}

// Get FCM tokens for multiple users (same as before)
func getFCMTokensForUsers(userUIDs []string) map[string]string {
	if len(userUIDs) == 0 {
		return make(map[string]string)
	}

	query := `
		SELECT DISTINCT firebase_uid, fcm_token
		FROM devices
		WHERE firebase_uid = ANY($1)
		AND fcm_token IS NOT NULL
		AND fcm_token != ''
		ORDER BY last_seen_at DESC
	`

	rows, err := db.Query(query, userUIDs)
	if err != nil {
		log.Printf("Error getting FCM tokens: %v", err)
		return make(map[string]string)
	}
	defer rows.Close()

	tokens := make(map[string]string)
	for rows.Next() {
		var uid, token string
		if err := rows.Scan(&uid, &token); err != nil {
			continue
		}
		tokens[uid] = token
	}

	log.Printf("Found FCM tokens for %d out of %d users", len(tokens), len(userUIDs))
	return tokens
}