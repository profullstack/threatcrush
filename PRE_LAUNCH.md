# Pre-Launch Checklist

## Environment Variables Needed

### Supabase (Required)
- `NEXT_PUBLIC_SUPABASE_URL` — Supabase project URL
- `NEXT_PUBLIC_SUPABASE_ANON_KEY` — Supabase anon/public key
- `SUPABASE_SERVICE_ROLE_KEY` — Supabase service role key (server-side only)

### Twilio (Needed for real SMS verification)
- `TWILIO_ACCOUNT_SID` — Twilio account SID
- `TWILIO_AUTH_TOKEN` — Twilio auth token
- `TWILIO_PHONE_NUMBER` — Twilio phone number for sending SMS

**Note:** Phone verification is currently STUBBED — accepts any 6-digit code. Replace the stub in `src/app/api/auth/verify-phone/route.ts` with real Twilio integration before launch.

## Auth System
- [x] Supabase Auth integration
- [x] Email + phone signup with verification
- [x] Login / logout
- [x] Account page with profile management
- [x] Referral code generation
- [ ] Real SMS OTP via Twilio
- [ ] Email verification callback handling (Supabase redirect URL config)

## Supabase Configuration
- [ ] Set email verification redirect URL in Supabase dashboard
- [ ] Enable email confirmations in Supabase Auth settings
- [ ] Run migration: `supabase/migrations/20260404160000_users.sql`
