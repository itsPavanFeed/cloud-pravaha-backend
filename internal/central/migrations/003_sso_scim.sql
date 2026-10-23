-- SSO: in-flight OIDC logins (single use, short-lived) and one-time codes that
-- the browser exchanges for a session token.
CREATE TABLE auth_flows (
    state      text PRIMARY KEY,
    verifier   text NOT NULL,
    nonce      text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE auth_codes (
    code_hash  bytea PRIMARY KEY,
    user_id    uuid NOT NULL REFERENCES users(id),
    expires_at timestamptz NOT NULL
);

-- SCIM provisioning: bearer tokens for the identity provider, and groups whose
-- names map to roles (pravaha:<tenant>:<role>, ...:entity:<slug>:<role>, ...:bu:<slug>:<role>).
CREATE TABLE scim_tokens (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name       text NOT NULL,
    token_hash bytea NOT NULL UNIQUE,
    created_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz
);
CREATE TABLE scim_groups (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    display_name text NOT NULL UNIQUE,
    external_id  text NOT NULL DEFAULT '',
    created_at   timestamptz NOT NULL DEFAULT now()
);
