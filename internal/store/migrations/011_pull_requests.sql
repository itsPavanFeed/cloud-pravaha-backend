-- Pull-request plans: a run can plan a pull request's version of a stack's spec;
-- the pull request is merged only after its changes are applied.
ALTER TABLE runs ADD COLUMN spec jsonb;        -- the spec this run plans and applies (NULL = the stack's)
ALTER TABLE runs ADD COLUMN pr_number integer;
ALTER TABLE runs ADD COLUMN pr_sha text;
CREATE INDEX runs_pr_idx ON runs (pr_number) WHERE pr_number IS NOT NULL;

ALTER TABLE stacks ADD COLUMN pr_number integer; -- proposed by an open pull request, not applied yet

CREATE TABLE pull_requests (
    number      integer PRIMARY KEY,
    repo        text NOT NULL,
    title       text NOT NULL DEFAULT '',
    author      text NOT NULL DEFAULT '',
    html_url    text NOT NULL DEFAULT '',
    head_sha    text NOT NULL,
    state       text NOT NULL DEFAULT 'open',  -- open | merged | closed
    results     jsonb NOT NULL DEFAULT '[]',   -- per contract: planned, unchanged, error, ...
    comment_id  bigint,
    comment_sum text NOT NULL DEFAULT '',      -- hash of the last comment body / status, to avoid re-posting
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    merged_at   timestamptz
);
