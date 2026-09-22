-- Message privacy: who can start a new conversation with you
ALTER TABLE profiles
  ADD COLUMN IF NOT EXISTS message_privacy VARCHAR(20) NOT NULL DEFAULT 'everyone'
  CHECK (message_privacy IN ('everyone', 'friends', 'nobody'));

-- Last seen privacy: who can see your online/last-seen status  
ALTER TABLE profiles
  ADD COLUMN IF NOT EXISTS last_seen_privacy VARCHAR(20) NOT NULL DEFAULT 'everyone'
  CHECK (last_seen_privacy IN ('everyone', 'friends', 'nobody'));
