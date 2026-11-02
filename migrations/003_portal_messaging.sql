BEGIN;

CREATE TABLE IF NOT EXISTS portal_messages (
  id UUID PRIMARY KEY,
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  approval_item_id UUID,
  message TEXT NOT NULL CHECK (length(message) BETWEEN 1 AND 5000),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  edited_at TIMESTAMPTZ,
  CONSTRAINT portal_messages_item_org_fk
    FOREIGN KEY (approval_item_id, organization_id)
    REFERENCES approval_items (id, organization_id)
    ON DELETE SET NULL (approval_item_id)
);

CREATE INDEX IF NOT EXISTS portal_messages_org_created_idx
  ON portal_messages (organization_id, created_at DESC);

CREATE INDEX IF NOT EXISTS portal_messages_item_created_idx
  ON portal_messages (approval_item_id, created_at ASC);

COMMIT;
