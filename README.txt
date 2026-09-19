OPAQUE MESSENGER - BACKEND SERVICE
====================================
Architecture: Core Messaging, WebRTC Calling, Group E2EE, Signal Protocol Keys

This repository contains the backend service for Opaque Messenger.
All extraneous features (AI processing, third-party payment gateways, daily tasks, social moments)
have been stripped out to ensure maximal speed, simplicity, and security.

CONTENTS:
---------
1. Core Backend Services:
   - main.go - Server routing, HTTP endpoints, WebSocket listener
   - hub.go - Real-time WebSocket connection manager & message router
   - device_handlers.go - Multi-device registration, device synchronization
   - key_handlers.go - Signal protocol PreKey bundle distribution & rotation
   - file_handlers.go - Encrypted attachment upload and retrieval
   - cleanup_job.go - Database maintenance and ephemeral message pruning
   - models.go - Request and response payload schemas
   - firebase_init.go - Firebase Admin SDK initialization for authentication
   - fcm_service.go - Push notifications via Firebase Cloud Messaging

2. Handlers (handlers/):
   - call_history.go - WebRTC audio/video call logging
   - turn_credentials.go - Dynamic TURN/STUN credential generator for WebRTC

3. Database:
   - schema.sql - PostgreSQL database schema
   - migrations/ - Database migration scripts

4. Configuration:
   - .env - Server environment variables (port, database URL, TURN secret)
   - serviceAccountKey.json - Firebase service account credentials

SETUP INSTRUCTIONS:
-------------------
1. Install Go 1.21+
2. Create PostgreSQL database:
   createdb opaque_db
3. Initialize database schema:
   psql -U postgres opaque_db < schema.sql
4. Provide .env and serviceAccountKey.json
5. Download dependencies:
   go mod download
6. Build:
   go build -o opaque-server .
7. Run:
   ./opaque-server
