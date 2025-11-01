-- Add down migration script here

-- Triggers
DROP TRIGGER IF EXISTS update_user_updated_at_trigger ON users;

-- Indices
DROP INDEX IF EXISTS idx_user_pid;
DROP INDEX IF EXISTS idx_user_email;

-- Tables
DROP TABLE IF EXISTS users;

-- Functions
DROP FUNCTION IF EXISTS update_timestamp;

-- Extensions
DROP EXTENSION IF EXISTS "uuid-ossp";
