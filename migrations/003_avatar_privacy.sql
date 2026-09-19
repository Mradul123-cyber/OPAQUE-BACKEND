-- Migration: 003_avatar_privacy.sql
-- Description: Add avatar_privacy column to profiles table with WhatsApp-style privacy controls

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 
        FROM information_schema.columns 
        WHERE table_name = 'profiles' AND column_name = 'avatar_privacy'
    ) THEN
        ALTER TABLE profiles 
        ADD COLUMN avatar_privacy VARCHAR(20) NOT NULL DEFAULT 'everyone';
        
        ALTER TABLE profiles 
        ADD CONSTRAINT chk_avatar_privacy 
        CHECK (avatar_privacy IN ('everyone', 'contacts', 'nobody'));

        RAISE NOTICE 'Added avatar_privacy column to profiles table';
    ELSE
        RAISE NOTICE 'avatar_privacy column already exists on profiles table';
    END IF;
END $$;
