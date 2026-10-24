-- Per-run limits on what one run may create or import (0 = no limit).
ALTER TABLE environments ADD COLUMN max_creates integer NOT NULL DEFAULT 0 CHECK (max_creates >= 0);
ALTER TABLE environments ADD COLUMN max_imports integer NOT NULL DEFAULT 0 CHECK (max_imports >= 0);
