-- Drift detection: refresh-only runs, scheduled per stack.
ALTER TABLE runs DROP CONSTRAINT runs_operation_check;
ALTER TABLE runs ADD CONSTRAINT runs_operation_check CHECK (operation IN ('apply', 'destroy', 'drift'));

ALTER TABLE stacks ADD COLUMN drift_interval_minutes integer NOT NULL DEFAULT 0 CHECK (drift_interval_minutes = 0 OR drift_interval_minutes >= 5);
ALTER TABLE stacks ADD COLUMN drift_auto_remediate boolean NOT NULL DEFAULT false;
ALTER TABLE stacks ADD COLUMN last_drift_check timestamptz;
