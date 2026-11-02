-- NeuralNext Engage production migration preflight
-- READ-ONLY. Run this BEFORE migrations 001–003.
-- Review every result. This script does not create or modify database objects.

-- 1. Confirm the existing approval_items table and columns required by migrations.
SELECT
  to_regclass('public.approval_items') AS approval_items_table,
  EXISTS (SELECT 1 FROM information_schema.columns
          WHERE table_schema='public' AND table_name='approval_items' AND column_name='payload') AS has_payload,
  EXISTS (SELECT 1 FROM information_schema.columns
          WHERE table_schema='public' AND table_name='approval_items' AND column_name='deleted_at') AS has_deleted_at,
  EXISTS (SELECT 1 FROM information_schema.columns
          WHERE table_schema='public' AND table_name='approval_items' AND column_name='submitted_at') AS has_submitted_at;

-- 2. Count records that will be assigned to each seeded organisation.
SELECT
  COALESCE(payload->>'client_name', 'Datasignz CreativeMinds') AS client_name,
  COUNT(*) AS approval_items,
  COUNT(*) FILTER (WHERE organization_id IS NULL) AS currently_unassigned
FROM approval_items
GROUP BY 1
ORDER BY 1;

-- 3. Identify rows whose client_name does not match one of the three known tenants.
SELECT id, request_id, payload->>'client_name' AS client_name, status
FROM approval_items
WHERE COALESCE(payload->>'client_name', 'Datasignz CreativeMinds')
  NOT IN ('Datasignz CreativeMinds', 'De Sportwekker', 'CleviaStudios')
ORDER BY submitted_at DESC
LIMIT 100;

-- 4. Confirm whether migration tables already exist (safe to run before/after).
SELECT
  to_regclass('public.organizations') AS organizations_table,
  to_regclass('public.users') AS users_table,
  to_regclass('public.organization_members') AS organization_members_table,
  to_regclass('public.organization_invitations') AS organization_invitations_table,
  to_regclass('public.user_sessions') AS user_sessions_table,
  to_regclass('public.client_review_actions') AS client_review_actions_table,
  to_regclass('public.portal_messages') AS portal_messages_table;

-- 5. If the portal tables already exist, inspect existing tenant mapping.
SELECT
  COUNT(*) AS total_items,
  COUNT(organization_id) AS assigned_items,
  COUNT(*) FILTER (WHERE organization_id IS NULL) AS unassigned_items
FROM approval_items;
