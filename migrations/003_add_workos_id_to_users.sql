-- Adds workos_id column to existing users table for WorkOS identity linking.
-- This migration assumes llmlens.users already exists.

ALTER TABLE llmlens.users ADD COLUMN IF NOT EXISTS workos_id varchar(255);

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_workos_id ON llmlens.users USING btree (workos_id);
