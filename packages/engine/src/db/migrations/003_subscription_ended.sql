-- A subscription the provider has ended for good.
--
-- Stripe does not guarantee webhook delivery order, and the replay guard on
-- payment_events cannot help: an update generated BEFORE a cancellation and
-- delivered after it is a genuinely different event with its own id. Such an
-- event flipped a cancelled subscription back to active and restored its paid
-- plan and monthly allowance indefinitely.
--
-- This column records that the subscription is over, so a stale update can be
-- refused. It is set from customer.subscription.deleted and from the two RAW
-- Stripe statuses that are terminal (`canceled`, `incomplete_expired`). It is
-- deliberately NOT set for `paused` or `unpaid`: SUBSCRIPTION_STATUS flattens
-- those onto 'canceled' too, but Stripe can move both back to active on the
-- same subscription id, and marking them terminal would lock a paying customer
-- out permanently.
ALTER TABLE subscriptions ADD COLUMN ended_at TEXT;

-- Backfill only where the event log proves a delete. Backfilling every
-- status='canceled' row would mark the paused/unpaid-flattened rows terminal
-- and lock those customers out — the exact failure this column exists to avoid.
UPDATE subscriptions SET ended_at = updated_at
 WHERE ended_at IS NULL AND status = 'canceled'
   AND EXISTS (
     SELECT 1 FROM payment_events pe
      WHERE pe.provider = subscriptions.provider
        AND pe.type = 'customer.subscription.deleted'
        AND json_extract(pe.payload_json, '$.id') = subscriptions.provider_subscription_id
   );
