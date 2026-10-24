-- Webhook deliveries from Git hosts (GitHub App), kept for troubleshooting.
CREATE TABLE webhook_deliveries (
    id          bigserial PRIMARY KEY,
    provider    text NOT NULL,
    delivery_id text NOT NULL,
    event       text NOT NULL,
    action      text NOT NULL DEFAULT '',
    repo        text NOT NULL DEFAULT '',
    ref         text NOT NULL DEFAULT '',
    sender      text NOT NULL DEFAULT '',
    outcome     text NOT NULL,           -- processed | ignored | rejected
    detail      text NOT NULL DEFAULT '',
    received_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (provider, delivery_id)
);
CREATE INDEX webhook_deliveries_received ON webhook_deliveries (received_at DESC);
