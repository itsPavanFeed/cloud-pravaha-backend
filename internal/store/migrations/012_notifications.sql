-- In-app notifications (also sent to Slack). Visibility follows the business
-- unit; tenant-wide events have bu = ''.
CREATE TABLE notifications (
    id         bigserial PRIMARY KEY,
    kind       text NOT NULL,              -- run.awaiting_approval, run.applied, drift.detected, ...
    severity   text NOT NULL,              -- info | action | success | warning | error
    title      text NOT NULL,
    body       text NOT NULL DEFAULT '',
    link       text NOT NULL DEFAULT '',   -- console path, e.g. runs/<id>
    bu         text NOT NULL DEFAULT '',
    entity     text NOT NULL DEFAULT '',
    run_id     uuid,
    steps      text[] NOT NULL DEFAULT '{}', -- approval steps still needed (for action buttons)
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX notifications_bu_idx ON notifications (bu, id DESC);

-- What each person has read: a watermark per user.
CREATE TABLE notification_reads (
    subject  text PRIMARY KEY,
    last_id  bigint NOT NULL DEFAULT 0
);
