ALTER TABLE tenants ADD COLUMN IF NOT EXISTS trial_ends_at timestamptz;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS current_period_end timestamptz;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS billing_provider text;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS provider_subscription_id text;
UPDATE tenants SET trial_ends_at=COALESCE(trial_ends_at,created_at+interval '14 days') WHERE status='TRIAL';
CREATE TABLE IF NOT EXISTS billing_events(
 id bigserial PRIMARY KEY, tenant_id uuid REFERENCES tenants(id) ON DELETE SET NULL,
 provider text NOT NULL, event_type text NOT NULL, provider_event_id text NOT NULL,
 payload jsonb NOT NULL DEFAULT '{}'::jsonb, processed_at timestamptz, created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(provider,provider_event_id,event_type)
);
CREATE INDEX IF NOT EXISTS idx_billing_events_created ON billing_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_tenants_billing ON tenants(status,plan,current_period_end);
