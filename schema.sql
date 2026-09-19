-- Zarq Messenger Database Schema
-- Clean professional schema with all tables, indexes, functions, and views

-- Drop existing tables if recreating (use carefully!)
-- Commented out by default for safety
/*
DROP TABLE IF EXISTS messages CASCADE;
DROP TABLE IF EXISTS conversation_members CASCADE;
DROP TABLE IF EXISTS friendships CASCADE;
DROP TABLE IF EXISTS conversations CASCADE;
DROP TABLE IF EXISTS profiles CASCADE;
DROP TABLE IF EXISTS identity_keys CASCADE;
DROP TABLE IF EXISTS signed_pre_keys CASCADE;
DROP TABLE IF EXISTS one_time_pre_keys CASCADE;
DROP TABLE IF EXISTS devices CASCADE;
DROP TABLE IF EXISTS message_status CASCADE;
DROP TABLE IF EXISTS pending_status_updates CASCADE;
DROP TABLE IF EXISTS offline_message_queue CASCADE;
DROP TABLE IF EXISTS message_deletions CASCADE;
DROP TABLE IF EXISTS shared_sessions CASCADE;
DROP TABLE IF EXISTS message_attachments CASCADE;
DROP TABLE IF EXISTS call_logs CASCADE;
DROP TABLE IF EXISTS group_sender_keys CASCADE;
DROP TABLE IF EXISTS group_invite_links CASCADE;
DROP TABLE IF EXISTS group_key_rotations CASCADE;
*/

-- =============================================================================
-- CORE TABLES
-- =============================================================================

-- Profiles: User accounts
CREATE TABLE IF NOT EXISTS profiles (
    firebase_uid TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    phone_hash TEXT UNIQUE,
    profile_avatar_url TEXT,
    display_name VARCHAR(100),
    avatar_privacy VARCHAR(20) NOT NULL DEFAULT 'everyone' CHECK (avatar_privacy IN ('everyone', 'contacts', 'nobody')),
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Devices: User devices for multi-device support
CREATE TABLE IF NOT EXISTS devices (
    firebase_uid TEXT NOT NULL REFERENCES profiles(firebase_uid) ON DELETE CASCADE,
    device_id INTEGER NOT NULL,
    device_name TEXT,
    platform TEXT, -- 'android', 'web', 'ios'
    push_token TEXT,
    last_seen_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    fcm_token TEXT,
    PRIMARY KEY (firebase_uid, device_id)
);

-- Conversations: Chat metadata (1-on-1 or group)
CREATE TABLE IF NOT EXISTS conversations (
    id SERIAL PRIMARY KEY,
    is_group BOOLEAN NOT NULL DEFAULT FALSE,
    group_name TEXT,
    creator_uid TEXT REFERENCES profiles(firebase_uid),
    group_avatar_url TEXT,
    description TEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    current_key_generation INTEGER DEFAULT 1,
    last_rotation_at TIMESTAMP DEFAULT NOW(),
    message_count_since_rotation INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Conversation Members: Links users to conversations
CREATE TABLE IF NOT EXISTS conversation_members (
    conversation_id INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    profile_uid TEXT NOT NULL REFERENCES profiles(firebase_uid) ON DELETE CASCADE,
    role VARCHAR(20) DEFAULT 'member',
    joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (conversation_id, profile_uid)
);

-- Friendships: Friend relationships and requests
CREATE TABLE IF NOT EXISTS friendships (
    user_a_uid TEXT NOT NULL REFERENCES profiles(firebase_uid) ON DELETE CASCADE,
    user_b_uid TEXT NOT NULL REFERENCES profiles(firebase_uid) ON DELETE CASCADE,
    status TEXT NOT NULL, -- 'pending', 'accepted', 'blocked'
    requester_uid TEXT NOT NULL REFERENCES profiles(firebase_uid) ON DELETE CASCADE,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_a_uid, user_b_uid)
);

-- =============================================================================
-- ENCRYPTION TABLES (Signal Protocol)
-- =============================================================================

-- Identity Keys: Long-term identity keys for each device
CREATE TABLE IF NOT EXISTS identity_keys (
    firebase_uid TEXT NOT NULL REFERENCES profiles(firebase_uid) ON DELETE CASCADE,
    device_id INTEGER NOT NULL DEFAULT 1,
    public_key BYTEA NOT NULL,
    registration_id INTEGER NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY (firebase_uid, device_id)
);

-- Signed Pre-Keys: Medium-term signed pre-keys
CREATE TABLE IF NOT EXISTS signed_pre_keys (
    key_id INTEGER NOT NULL,
    firebase_uid TEXT NOT NULL REFERENCES profiles(firebase_uid) ON DELETE CASCADE,
    device_id INTEGER NOT NULL DEFAULT 1,
    public_key BYTEA NOT NULL,
    signature BYTEA NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY (firebase_uid, device_id, key_id)
);

-- One-Time Pre-Keys: Single-use pre-keys for initial handshake
CREATE TABLE IF NOT EXISTS one_time_pre_keys (
    key_id INTEGER NOT NULL,
    firebase_uid TEXT NOT NULL REFERENCES profiles(firebase_uid) ON DELETE CASCADE,
    device_id INTEGER NOT NULL DEFAULT 1,
    public_key BYTEA NOT NULL,
    consumed BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY (firebase_uid, device_id, key_id)
);

-- Group Sender Keys: For group chat encryption
CREATE TABLE IF NOT EXISTS group_sender_keys (
    id SERIAL PRIMARY KEY,
    conversation_id INTEGER REFERENCES conversations(id),
    sender_uid TEXT NOT NULL,
    device_id INTEGER NOT NULL,
    sender_key_distribution TEXT NOT NULL, -- Base64 encoded
    created_at TIMESTAMP,
    key_generation INTEGER DEFAULT 1,
    rotated_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(conversation_id, sender_uid, device_id)
);

-- Group Key Rotations: Track key rotation events
CREATE TABLE IF NOT EXISTS group_key_rotations (
    id SERIAL PRIMARY KEY,
    conversation_id INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    rotation_reason VARCHAR(50) NOT NULL, -- 'member_removed', 'member_added', 'manual', 'periodic'
    triggered_by_uid VARCHAR(255),
    old_generation INTEGER NOT NULL,
    new_generation INTEGER NOT NULL,
    affected_member_uid VARCHAR(255), -- UID of removed/added member
    created_at TIMESTAMP DEFAULT NOW()
);

-- Shared Sessions: For session sharing between devices
CREATE TABLE IF NOT EXISTS shared_sessions (
    id SERIAL PRIMARY KEY,
    session_key TEXT NOT NULL UNIQUE,
    session_data BYTEA NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    last_updated TIMESTAMP DEFAULT NOW(),
    created_by TEXT NOT NULL
);

-- =============================================================================
-- MESSAGE TABLES
-- =============================================================================

-- Messages: Encrypted message content
CREATE TABLE IF NOT EXISTS messages (
    id SERIAL PRIMARY KEY,
    conversation_id INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    sender_uid TEXT NOT NULL REFERENCES profiles(firebase_uid),
    status TEXT DEFAULT 'sent',
    sender_device_id INTEGER NOT NULL DEFAULT 1,
    content BYTEA NOT NULL, -- Binary encrypted ciphertext
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    deleted_for_everyone BOOLEAN DEFAULT FALSE,
    message_type TEXT DEFAULT 'chat', -- 'chat', 'system', 'ephemeral'
    ephemeral_expires_at TIMESTAMPTZ,
    metadata JSONB,
    CONSTRAINT chk_sender_device_id_positive CHECK (sender_device_id > 0)
);

-- Message Status: Delivery and read receipts
CREATE TABLE IF NOT EXISTS message_status (
    message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    recipient_uid TEXT NOT NULL REFERENCES profiles(firebase_uid) ON DELETE CASCADE,
    recipient_device_id INTEGER NOT NULL DEFAULT 1,
    delivered_at TIMESTAMPTZ,
    read_at TIMESTAMPTZ,
    PRIMARY KEY (message_id, recipient_uid, recipient_device_id)
);

-- Message Deletions: Track message deletion events
CREATE TABLE IF NOT EXISTS message_deletions (
    id SERIAL PRIMARY KEY,
    message_id INT REFERENCES messages(id),
    deleted_by_uid TEXT NOT NULL,
    deletion_type TEXT NOT NULL, -- 'delete_for_me', 'delete_for_everyone'
    deleted_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(message_id, deleted_by_uid)
);

-- Message Attachments: Files, images, videos, audio
CREATE TABLE IF NOT EXISTS message_attachments (
    id SERIAL PRIMARY KEY,
    message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    file_type TEXT NOT NULL, -- 'image', 'video', 'document', 'audio'
    mime_type TEXT NOT NULL,
    file_size BIGINT NOT NULL,
    encrypted_file_path TEXT NOT NULL,
    thumbnail_path TEXT,
    width INTEGER,
    height INTEGER,
    duration INTEGER, -- For video/audio in seconds
    media_encryption_key TEXT,
    media_encryption_iv TEXT,
    sender_viewed_at TIMESTAMP WITH TIME ZONE,
    recipient_viewed_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Pending Status Updates: Queue for status update syncing
CREATE TABLE IF NOT EXISTS pending_status_updates (
    id SERIAL PRIMARY KEY,
    user_uid TEXT NOT NULL,
    message_id INTEGER NOT NULL,
    status TEXT NOT NULL,
    conversation_id INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(user_uid, message_id, status)
);

-- Offline Message Queue: Messages for offline users
CREATE TABLE IF NOT EXISTS offline_message_queue (
    id SERIAL PRIMARY KEY,
    recipient_uid TEXT NOT NULL,
    sender_uid TEXT NOT NULL,
    conversation_id INT REFERENCES conversations(id),
    message_id INT REFERENCES messages(id),
    encrypted_content BYTEA,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    delivered BOOLEAN DEFAULT FALSE,
    delivered_at TIMESTAMPTZ,
    delivery_attempts INT DEFAULT 0,
    max_attempts INT DEFAULT 3,
    session_context BYTEA,
    message_type TEXT DEFAULT 'new_message',
    message_data JSONB
);

-- =============================================================================
-- CALL TABLES
-- =============================================================================

-- Call Logs: Voice and video call history
CREATE TABLE IF NOT EXISTS call_logs (
    id SERIAL PRIMARY KEY,
    caller_uid TEXT NOT NULL REFERENCES profiles(firebase_uid) ON DELETE CASCADE,
    receiver_uid TEXT NOT NULL REFERENCES profiles(firebase_uid) ON DELETE CASCADE,
    call_type TEXT NOT NULL CHECK (call_type IN ('voice', 'video')),
    call_status TEXT NOT NULL DEFAULT 'initiated' CHECK (call_status IN ('initiated', 'connected', 'completed', 'rejected', 'missed', 'failed')),
    conversation_id INTEGER REFERENCES conversations(id),
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ended_at TIMESTAMPTZ,
    duration_seconds INTEGER,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- =============================================================================
-- GROUP MANAGEMENT TABLES
-- =============================================================================

-- Group Invite Links: Shareable group join links
CREATE TABLE IF NOT EXISTS group_invite_links (
    invite_code VARCHAR(32) PRIMARY KEY,
    conversation_id INTEGER REFERENCES conversations(id) ON DELETE CASCADE,
    created_by TEXT REFERENCES profiles(firebase_uid),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    is_active BOOLEAN DEFAULT true
);

-- =============================================================================
-- INDEXES FOR PERFORMANCE
-- =============================================================================

CREATE UNIQUE INDEX IF NOT EXISTS idx_profiles_username_lower ON profiles (LOWER(username));
CREATE INDEX IF NOT EXISTS idx_profiles_phone_hash ON profiles (phone_hash) WHERE phone_hash IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_messages_conversation_id ON messages(conversation_id);
CREATE INDEX IF NOT EXISTS idx_messages_conversation_created ON messages(conversation_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender_uid);

CREATE INDEX IF NOT EXISTS idx_friendships_user_a ON friendships(user_a_uid);
CREATE INDEX IF NOT EXISTS idx_friendships_user_b ON friendships(user_b_uid);

CREATE INDEX IF NOT EXISTS idx_identity_keys_user ON identity_keys(firebase_uid);
CREATE INDEX IF NOT EXISTS idx_signed_prekeys_user ON signed_pre_keys(firebase_uid);
CREATE INDEX IF NOT EXISTS idx_one_time_pre_keys_unconsumed ON one_time_pre_keys(firebase_uid, device_id) WHERE consumed = false;

CREATE INDEX IF NOT EXISTS idx_devices_user ON devices(firebase_uid);
CREATE INDEX IF NOT EXISTS idx_devices_fcm_token ON devices(fcm_token) WHERE fcm_token IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_message_status_recipient ON message_status(recipient_uid, recipient_device_id);
CREATE INDEX IF NOT EXISTS idx_message_status_message ON message_status(message_id);

CREATE INDEX IF NOT EXISTS idx_offline_queue_recipient ON offline_message_queue(recipient_uid, delivered);
CREATE INDEX IF NOT EXISTS idx_offline_queue_created ON offline_message_queue(created_at);

CREATE INDEX IF NOT EXISTS idx_shared_sessions_key ON shared_sessions(session_key);
CREATE INDEX IF NOT EXISTS idx_shared_sessions_updated ON shared_sessions(last_updated);

CREATE INDEX IF NOT EXISTS idx_message_attachments_message_id ON message_attachments(message_id);
CREATE INDEX IF NOT EXISTS idx_message_attachments_cleanup ON message_attachments(created_at, sender_viewed_at, recipient_viewed_at);

CREATE INDEX IF NOT EXISTS idx_call_logs_caller ON call_logs(caller_uid);
CREATE INDEX IF NOT EXISTS idx_call_logs_receiver ON call_logs(receiver_uid);
CREATE INDEX IF NOT EXISTS idx_call_logs_started ON call_logs(started_at);
CREATE INDEX IF NOT EXISTS idx_call_logs_conversation ON call_logs(conversation_id);

CREATE INDEX IF NOT EXISTS idx_sender_keys_conversation ON group_sender_keys(conversation_id);
CREATE INDEX IF NOT EXISTS idx_sender_keys_generation ON group_sender_keys(conversation_id, key_generation);

CREATE INDEX IF NOT EXISTS idx_conversation_members_role ON conversation_members(role);

CREATE INDEX IF NOT EXISTS idx_group_invite_links_active ON group_invite_links(conversation_id, is_active);

CREATE INDEX IF NOT EXISTS idx_key_rotations_conversation ON group_key_rotations(conversation_id);

-- =============================================================================
-- FUNCTIONS
-- =============================================================================

-- Function to atomically consume a one-time pre-key
CREATE OR REPLACE FUNCTION consume_one_time_prekey(
    p_uid TEXT,
    p_device INTEGER
)
RETURNS TABLE(
    firebase_uid TEXT,
    device_id INTEGER,
    key_id INTEGER,
    public_key_b64 TEXT
)
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    WITH candidate AS (
        SELECT otp.firebase_uid, otp.device_id, otp.key_id, otp.public_key
        FROM one_time_pre_keys otp
        WHERE otp.firebase_uid = p_uid
        AND otp.device_id = p_device
        AND otp.consumed = false
        ORDER BY otp.key_id
        FOR UPDATE SKIP LOCKED
        LIMIT 1
    )
    UPDATE one_time_pre_keys k
    SET consumed = true
    FROM candidate c
    WHERE k.firebase_uid = c.firebase_uid
    AND k.device_id = c.device_id
    AND k.key_id = c.key_id
    RETURNING k.firebase_uid, k.device_id, k.key_id, encode(k.public_key, 'base64') AS public_key_b64;
END;
$$;

-- =============================================================================
-- VIEWS
-- =============================================================================

-- View for fetching complete pre-key bundles
CREATE OR REPLACE VIEW prekey_bundles AS
SELECT
    ik.firebase_uid,
    ik.device_id,
    encode(ik.public_key, 'base64') AS identity_key_b64,
    ik.registration_id,
    spk.key_id AS signed_prekey_id,
    encode(spk.public_key, 'base64') AS signed_prekey_b64,
    encode(spk.signature, 'base64') AS signed_prekey_signature_b64,
    (
        SELECT COUNT(*)
        FROM one_time_pre_keys otp
        WHERE otp.firebase_uid = ik.firebase_uid
        AND otp.device_id = ik.device_id
        AND otp.consumed = false
    ) AS one_time_prekeys_available,
    GREATEST(ik.created_at, spk.created_at) AS bundle_created_at
FROM identity_keys ik
LEFT JOIN signed_pre_keys spk
    ON spk.firebase_uid = ik.firebase_uid
    AND spk.device_id = ik.device_id;
