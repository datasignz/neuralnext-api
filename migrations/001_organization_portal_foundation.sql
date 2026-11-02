-- NeuralNext Engage: organisation and client-portal foundation
-- Migration 001: additive schema only. Review and back up production before execution.
-- This file is intentionally NOT executed automatically by server.js.

BEGIN;

CREATE TABLE IF NOT EXISTS organizations (
  id UUID PRIMARY KEY,
  name TEXT NOT NULL,
  slug TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL DEFAULT 'active'
    CHECK (status IN ('active', 'suspended', 'archived')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY,
  email TEXT NOT NULL,
  full_name TEXT,
  password_hash TEXT,
  status TEXT NOT NULL DEFAULT 'invited'
    CHECK (status IN ('invited', 'active', 'suspended')),
  email_verified_at TIMESTAMPTZ,
  last_login_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS users_email_lower_unique_idx
  ON users (LOWER(email));

CREATE TABLE IF NOT EXISTS organization_members (
  id UUID PRIMARY KEY,
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role TEXT NOT NULL CHECK (role IN (
    'owner',
    'admin',
    'social_media_manager',
    'content_editor',
    'client',
    'guest'
  )),
  status TEXT NOT NULL DEFAULT 'active'
    CHECK (status IN ('active', 'suspended', 'removed')),
  invited_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (organization_id, user_id)
);

CREATE INDEX IF NOT EXISTS organization_members_user_idx
  ON organization_members (user_id, status);
CREATE INDEX IF NOT EXISTS organization_members_org_idx
  ON organization_members (organization_id, status);

CREATE TABLE IF NOT EXISTS organization_invitations (
  id UUID PRIMARY KEY,
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  email TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN (
    'owner',
    'admin',
    'social_media_manager',
    'content_editor',
    'client',
    'guest'
  )),
  token_hash TEXT NOT NULL UNIQUE,
  invited_by UUID REFERENCES users(id) ON DELETE SET NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  accepted_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS organization_invitations_org_email_idx
  ON organization_invitations (organization_id, LOWER(email));

CREATE TABLE IF NOT EXISTS user_sessions (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS user_sessions_user_active_idx
  ON user_sessions (user_id, expires_at)
  WHERE revoked_at IS NULL;

ALTER TABLE approval_items
  ADD COLUMN IF NOT EXISTS organization_id UUID
  REFERENCES organizations(id) ON DELETE RESTRICT;

-- Seed the three organisations already represented in the existing dashboard.
INSERT INTO organizations (id, name, slug)
VALUES
  ('10000000-0000-4000-8000-000000000001', 'Datasignz CreativeMinds', 'datasignz-creativeminds'),
  ('10000000-0000-4000-8000-000000000002', 'De Sportwekker', 'de-sportwekker'),
  ('10000000-0000-4000-8000-000000000003', 'CleviaStudios', 'cleviastudios')
ON CONFLICT (slug) DO UPDATE
SET name = EXCLUDED.name,
    updated_at = NOW();

-- Backfill existing approval records using the client_name already stored in payload.
UPDATE approval_items AS a
SET organization_id = o.id
FROM organizations AS o
WHERE a.organization_id IS NULL
  AND (
    (o.slug = 'datasignz-creativeminds'
      AND COALESCE(a.payload->>'client_name', 'Datasignz CreativeMinds') = 'Datasignz CreativeMinds')
    OR
    (o.slug = 'de-sportwekker'
      AND a.payload->>'client_name' = 'De Sportwekker')
    OR
    (o.slug = 'cleviastudios'
      AND a.payload->>'client_name' = 'CleviaStudios')
  );

-- Automatically assign organisation scope to future approval submissions.
-- Existing submit endpoints write payload.client_name but do not write organization_id.
CREATE OR REPLACE FUNCTION set_approval_item_organization()
RETURNS TRIGGER AS $
DECLARE
  client_slug TEXT;
BEGIN
  IF NEW.organization_id IS NULL THEN
    client_slug := CASE
      WHEN COALESCE(NEW.payload->>'client_name', 'Datasignz CreativeMinds') = 'Datasignz CreativeMinds'
        THEN 'datasignz-creativeminds'
      WHEN NEW.payload->>'client_name' = 'De Sportwekker'
        THEN 'de-sportwekker'
      WHEN NEW.payload->>'client_name' = 'CleviaStudios'
        THEN 'cleviastudios'
      ELSE NULL
    END;

    IF client_slug IS NOT NULL THEN
      SELECT id INTO NEW.organization_id
      FROM organizations
      WHERE slug = client_slug AND status = 'active';
    END IF;
  END IF;

  RETURN NEW;
END;
$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS approval_items_set_organization ON approval_items;
CREATE TRIGGER approval_items_set_organization
BEFORE INSERT OR UPDATE OF payload, organization_id
ON approval_items
FOR EACH ROW
EXECUTE FUNCTION set_approval_item_organization();

CREATE INDEX IF NOT EXISTS approval_items_organization_status_submitted_idx
  ON approval_items (organization_id, status, submitted_at DESC);

CREATE INDEX IF NOT EXISTS approval_items_organization_deleted_idx
  ON approval_items (organization_id, deleted_at);

COMMIT;

-- Post-migration verification:
-- SELECT name, slug, id FROM organizations ORDER BY name;
-- SELECT COUNT(*) AS total_items,
--        COUNT(organization_id) AS linked_items,
--        COUNT(*) FILTER (WHERE organization_id IS NULL) AS unlinked_items
-- FROM approval_items;
-- SELECT COALESCE(payload->>'client_name', 'Datasignz CreativeMinds') AS client,
--        COUNT(*) AS total,
--        COUNT(organization_id) AS linked
-- FROM approval_items
-- GROUP BY 1
-- ORDER BY 1;
