ALTER TABLE tenants
  ADD COLUMN billing_checkout_id uuid,
  ADD COLUMN billing_checkout_plan text,
  ADD COLUMN billing_provider_modified_at timestamptz,
  ADD COLUMN billing_last_charge_at timestamptz;
