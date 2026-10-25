-- Releases come from a branch, a pull request or a change made in the console
-- (committed as a pull request once it builds). Activating one needs DevOps
-- approvals; activating a pull-request release merges the pull request.
ALTER TABLE releases ADD COLUMN origin text NOT NULL DEFAULT 'branch' CHECK (origin IN ('branch', 'pr', 'console'));
ALTER TABLE releases ADD COLUMN ref text NOT NULL DEFAULT '';          -- branch name
ALTER TABLE releases ADD COLUMN pr_number integer;
ALTER TABLE releases ADD COLUMN pr_url text;
ALTER TABLE releases ADD COLUMN title text NOT NULL DEFAULT '';        -- PR title or change summary
ALTER TABLE releases ADD COLUMN requested_by text;                     -- asked for activation
ALTER TABLE releases ADD COLUMN requested_at timestamptz;
ALTER TABLE releases ADD COLUMN merge_sha text;                        -- merge commit after activation
ALTER TABLE releases ADD COLUMN merge_error text;
ALTER TABLE releases DROP CONSTRAINT releases_status_check;
ALTER TABLE releases ADD CONSTRAINT releases_status_check
    CHECK (status IN ('building', 'failed', 'ready', 'pending', 'active', 'superseded', 'discarded'));
-- Several builds may run at once now (one per branch or pull request).
DROP INDEX releases_one_building;
CREATE UNIQUE INDEX releases_one_pending ON releases (kind) WHERE status = 'pending';

CREATE TABLE release_approvals (
    release_id uuid NOT NULL REFERENCES releases(id) ON DELETE CASCADE,
    approver   text NOT NULL,
    decision   text NOT NULL CHECK (decision IN ('approve', 'reject', 'override')),
    reason     text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (release_id, approver)
);
