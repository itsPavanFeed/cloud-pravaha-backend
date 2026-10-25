-- Drift checks are started by people only: scheduled checks and automatic
-- remediation are gone (the columns stay for older rows, always off).
UPDATE stacks SET drift_interval_minutes = 0, drift_auto_remediate = false;
