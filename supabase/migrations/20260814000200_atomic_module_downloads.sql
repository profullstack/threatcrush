-- TC-24: the install route did read-modify-write on modules.downloads
-- (`newCount = downloads + 1` in JS, then UPDATE), so concurrent installs
-- overwrote each other and the count drifted low. Do the increment in the
-- database, where it is atomic.

create or replace function public.increment_module_downloads(p_module_id uuid)
returns integer
language sql
security definer
set search_path = ''
as $$
  update public.modules
     set downloads = coalesce(downloads, 0) + 1,
         updated_at = now()
   where id = p_module_id
  returning downloads;
$$;

revoke all on function public.increment_module_downloads(uuid) from public;
grant execute on function public.increment_module_downloads(uuid) to service_role;
