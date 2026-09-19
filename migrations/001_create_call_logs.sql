-- Create call_logs table for minimal call metadata logging
-- Purpose: Abuse prevention, debugging, legal compliance
-- Retention: 30 days (auto-deleted)

CREATE TABLE IF NOT EXISTS call_logs (
    id SERIAL PRIMARY KEY,
    caller_uid VARCHAR(255) NOT NULL,
    receiver_uid VARCHAR(255) NOT NULL,
    call_type VARCHAR(10) NOT NULL CHECK (call_type IN ('voice', 'video')),
    started_at TIMESTAMP NOT NULL DEFAULT NOW(),
    ended_at TIMESTAMP,
    duration_seconds INT,
    call_status VARCHAR(20) NOT NULL DEFAULT 'initiated' CHECK (call_status IN ('initiated', 'connected', 'completed', 'rejected', 'missed', 'failed')),
    conversation_id INT REFERENCES conversations(id),
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),

    -- Indexes for performance
    INDEX idx_caller_uid (caller_uid),
    INDEX idx_receiver_uid (receiver_uid),
    INDEX idx_started_at (started_at),
    INDEX idx_conversation_id (conversation_id)
);

-- Add comment explaining the purpose
COMMENT ON TABLE call_logs IS 'Minimal call metadata for abuse prevention and debugging. Auto-deleted after 30 days.';
COMMENT ON COLUMN call_logs.caller_uid IS 'Firebase UID of the user initiating the call';
COMMENT ON COLUMN call_logs.receiver_uid IS 'Firebase UID of the user receiving the call';
COMMENT ON COLUMN call_logs.call_type IS 'Type of call: voice or video';
COMMENT ON COLUMN call_logs.call_status IS 'Final status of the call';
COMMENT ON COLUMN call_logs.duration_seconds IS 'Call duration in seconds (only for completed calls)';
