-- Migration 002: Make phone_hash nullable for email and Google authentication
-- Transactional migration with non-destructive case-collision preflight.

BEGIN;

-- 1. Non-destructive collision preflight:
-- Ensure no case-colliding usernames exist before attempting to create the unique index.
DO $$
DECLARE
    collision_count INT;
    sample_collisions TEXT;
BEGIN
    SELECT COUNT(*), COALESCE(string_agg(sub.lower_username, ', '), '')
    INTO collision_count, sample_collisions
    FROM (
        SELECT LOWER(username) AS lower_username
        FROM profiles
        GROUP BY LOWER(username)
        HAVING COUNT(*) > 1
        LIMIT 5
    ) sub;
    
    IF collision_count > 0 THEN
        RAISE EXCEPTION 'Preflight check failed: Found % case-colliding username groups in profiles (e.g. %). Please resolve duplicate usernames before running this migration.', collision_count, sample_collisions;
    END IF;
END $$;

-- 2. Drop NOT NULL constraint on phone_hash (nullable for email and Google users)
ALTER TABLE profiles ALTER COLUMN phone_hash DROP NOT NULL;

-- 3. Clean up any empty strings or hash-of-empty-string from legacy registration attempts
UPDATE profiles 
SET phone_hash = NULL 
WHERE phone_hash = '' 
   OR phone_hash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

-- 4. Case-insensitive unique index on username to prevent mixed-case collisions
CREATE UNIQUE INDEX IF NOT EXISTS idx_profiles_username_lower ON profiles (LOWER(username));

COMMIT;
