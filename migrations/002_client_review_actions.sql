BEGIN;

-- Require an approval item + organisation pair to be unique so review actions
-- cannot reference an approval item under a different organisation.
CREATE UNIQUE INDEX IF NOT EXISTS approval_items_id_organization_unique_idx
  ON approval_items (id, organization_id);

CREATE TABLE IF NOT EXISTS client_review_actions (
 id UUID PRIMARY KEY,
 approval_item_id UUID NOT NULL,
 organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
 user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
 action TEXT NOT NULL CHECK (action IN ('approved_by_client','rejected_by_client','revision_requested')),
 message TEXT,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 CONSTRAINT client_review_actions_item_org_fk
   FOREIGN KEY (approval_item_id, organization_id)
   REFERENCES approval_items (id, organization_id)
   ON DELETE CASCADE
);

-- If this migration is applied to a database where the table already exists,
-- add the composite tenant-integrity constraint without replacing existing data.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'client_review_actions_item_org_fk'
      AND conrelid = 'client_review_actions'::regclass
  ) THEN
    ALTER TABLE client_review_actions
      ADD CONSTRAINT client_review_actions_item_org_fk
      FOREIGN KEY (approval_item_id, organization_id)
      REFERENCES approval_items (id, organization_id)
      ON DELETE CASCADE;
  END IF;
END;
$$;

CREATE INDEX IF NOT EXISTS client_review_actions_org_created_idx
  ON client_review_actions (organization_id, created_at DESC);
CREATE INDEX IF NOT EXISTS client_review_actions_item_created_idx
  ON client_review_actions (approval_item_id, created_at DESC);

COMMIT;
