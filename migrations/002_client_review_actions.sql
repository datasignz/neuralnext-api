BEGIN;
CREATE TABLE IF NOT EXISTS client_review_actions (
 id UUID PRIMARY KEY,
 approval_item_id UUID NOT NULL REFERENCES approval_items(id) ON DELETE CASCADE,
 organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
 user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
 action TEXT NOT NULL CHECK (action IN ('approved_by_client','rejected_by_client','revision_requested')),
 message TEXT,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS client_review_actions_org_created_idx ON client_review_actions (organization_id, created_at DESC);
CREATE INDEX IF NOT EXISTS client_review_actions_item_created_idx ON client_review_actions (approval_item_id, created_at DESC);
COMMIT;
