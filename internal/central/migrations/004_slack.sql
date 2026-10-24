-- Slack app credentials per tenant for interactive approvals (sealed with the
-- central master key): the signing secret verifies Slack's requests, the bot
-- token resolves the clicking user's email.
CREATE TABLE tenant_slack (
    tenant_id      uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    signing_secret bytea NOT NULL,
    bot_token      bytea NOT NULL,
    updated_by     text NOT NULL,
    updated_at     timestamptz NOT NULL DEFAULT now()
);
