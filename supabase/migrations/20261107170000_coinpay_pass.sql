-- Profullstack Pass (2026-11-07): a CoinPay user who deposits $99 into their
-- own CoinPay wallet gets a free month on every Profullstack property.
-- ThreatCrush's balance is pay-as-you-go credit (credit_deposits minus
-- usage_events), so a pass pays the smallest top-up ($1 = 1 scan credit) once
-- per pass through grant_code_credits() with grant_source
-- 'coinpay-pass:<sub>:<expires_at>' (credit_deposits_grant_source_uniq keeps
-- it once per user; coinpay_identities.sub is unique, so once per pass).
--
-- coinpay_identities.pass_until: the pass expiry CoinPay reported at the last
-- sign-in (the claim is only seen then). Additive only.

alter table public.coinpay_identities add column if not exists pass_until timestamptz;
