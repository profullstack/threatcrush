-- Lock SECURITY DEFINER functions that the anon key could call.
--
-- Supabase grants EXECUTE on every new function to anon and authenticated, so on
-- 2026-10-26 eight SECURITY DEFINER functions in public were callable with the public
-- anon key. Every application caller uses getSupabaseAdmin() (service role), so the
-- server-side ones move to service_role only. No function bodies change.
--
--   claim_next_property_run(worker, org_ids): anyone could claim (and reset the leases
--     of) any organisation's property runs and read the claimed rows.
--   bump_outrank_integration, increment_module_downloads: counters, internal.
--   record_reader_progress / record_reader_checklist: reader beacons, written by
--     /api/reader-events and /api/checklist with the service role.
--   guard_privileged_profile_columns, handle_new_organization: trigger functions.
--
-- current_user_is_admin() stays callable: it only reads the caller's own row and two
-- user_profiles policies (TO public) depend on it.
--
-- Also: two leftover blog_posts_bak_* tables had RLS off with full anon grants, and new
-- functions no longer default to EXECUTE for PUBLIC or anon.

DO $$
DECLARE
    fn text;
    sig text;
    names text[] := ARRAY[
        'bump_outrank_integration','claim_next_property_run','guard_privileged_profile_columns',
        'handle_new_organization','increment_module_downloads','record_reader_checklist',
        'record_reader_progress'
    ];
BEGIN
    FOREACH fn IN ARRAY names LOOP
        FOR sig IN
            SELECT format('public.%I(%s)', p.proname, pg_get_function_identity_arguments(p.oid))
            FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
            WHERE n.nspname = 'public' AND p.proname = fn
        LOOP
            EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC, anon, authenticated', sig);
            EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO service_role', sig);
        END LOOP;
    END LOOP;
END $$;

ALTER TABLE IF EXISTS public.blog_posts_bak_20261014 ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS public.blog_posts_bak_20261017_links ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.blog_posts_bak_20261014 FROM anon, authenticated;
REVOKE ALL ON TABLE public.blog_posts_bak_20261017_links FROM anon, authenticated;

ALTER DEFAULT PRIVILEGES FOR ROLE postgres REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public REVOKE EXECUTE ON FUNCTIONS FROM anon;

NOTIFY pgrst, 'reload schema';
