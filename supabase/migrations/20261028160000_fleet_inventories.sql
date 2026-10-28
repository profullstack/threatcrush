-- Fleet inventories: one OpenDevice document per organization
-- (https://logicsrc.com/docs/opendevice). It lists every machine the org runs,
-- daemon or not, with what each one costs, so the dashboard's Fleet panel can
-- show boxes that never installed ThreatCrush plus a monthly total, and CoinPay
-- can pull the recurring costs from GET /api/fleet/costs.
--
-- The API validates the document with @profullstack/fleet before it is stored
-- (PUT /api/orgs/:id/inventory, org owner/admin only) and reads it with the
-- service role. The policies below are the same rule for any direct
-- authenticated read: owner/admin/member read (guests do not: costs are
-- org-wide, not per fleet), owner/admin write.

create table if not exists public.fleet_inventories (
  org_id uuid primary key references public.organizations(id) on delete cascade,
  document jsonb not null,
  updated_at timestamptz not null default now(),
  updated_by uuid references auth.users(id) on delete set null
);

alter table public.fleet_inventories enable row level security;

drop policy if exists fleet_inventories_member_select on public.fleet_inventories;
create policy fleet_inventories_member_select on public.fleet_inventories
  for select to authenticated
  using (
    org_id in (
      select org_id from public.organization_members
      where user_id = auth.uid() and role in ('owner', 'admin', 'member')
    )
  );

drop policy if exists fleet_inventories_admin_manage on public.fleet_inventories;
create policy fleet_inventories_admin_manage on public.fleet_inventories
  for all to authenticated
  using (
    org_id in (
      select org_id from public.organization_members
      where user_id = auth.uid() and role in ('owner', 'admin')
    )
  )
  with check (
    org_id in (
      select org_id from public.organization_members
      where user_id = auth.uid() and role in ('owner', 'admin')
    )
  );

drop policy if exists fleet_inventories_service_role_all on public.fleet_inventories;
create policy fleet_inventories_service_role_all on public.fleet_inventories
  for all to service_role using (true) with check (true);

revoke all on public.fleet_inventories from anon;
revoke all on public.fleet_inventories from authenticated;
grant select, insert, update, delete on public.fleet_inventories to authenticated;
