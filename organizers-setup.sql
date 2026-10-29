-- Trip Book: owner can name organizers, each with a personal code.
-- Run once in Supabase (birdie book) > SQL Editor > New query > Run.
-- Your owner code is the organizer code you set in privacy-setup.sql (nothing to change here).

create table if not exists public.trip_organizers (
  code text primary key,
  name text not null,
  created_at timestamptz not null default now()
);
alter table public.trip_organizers enable row level security;
revoke all on public.trip_organizers from anon, authenticated;
create unique index if not exists trip_organizers_code_lower on public.trip_organizers (lower(code));

create or replace function public.org_owner_match(p_owner text) returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from app_settings where key = 'organizer_code' and lower(trim(value)) = lower(trim(coalesce(p_owner,''))));
$$;

create or replace function public.org_is_owner(p_owner text) returns boolean language plpgsql security definer set search_path = public as $$
begin
  perform trip_throttle();
  if org_owner_match(p_owner) then return true; end if;
  perform trip_fail(); return false;
end $$;

create or replace function public.org_list(p_owner text) returns table(name text, code text, created_at timestamptz) language plpgsql security definer set search_path = public as $$
begin
  perform trip_throttle();
  if not org_owner_match(p_owner) then perform trip_fail(); return; end if;
  return query select o.name, o.code, o.created_at from trip_organizers o order by o.name;
end $$;

create or replace function public.org_add(p_owner text, p_name text, p_code text) returns text language plpgsql security definer set search_path = public as $$
begin
  perform trip_throttle();
  if not org_owner_match(p_owner) then perform trip_fail(); return 'not-owner'; end if;
  if length(trim(coalesce(p_name,''))) = 0 then return 'no-name'; end if;
  if length(trim(coalesce(p_code,''))) < 8 then return 'too-weak'; end if;
  if exists (select 1 from trip_organizers where lower(code) = lower(trim(p_code))) or org_owner_match(p_code) then return 'taken'; end if;
  insert into trip_organizers (code, name) values (upper(trim(p_code)), trim(p_name));
  return 'ok';
end $$;

create or replace function public.org_remove(p_owner text, p_code text) returns text language plpgsql security definer set search_path = public as $$
begin
  perform trip_throttle();
  if not org_owner_match(p_owner) then perform trip_fail(); return 'not-owner'; end if;
  delete from trip_organizers where lower(code) = lower(trim(coalesce(p_code,'')));
  return 'ok';
end $$;

-- New trips: the owner code OR any organizer's code works. Records who started it.
create or replace function public.trip_create(p_trip text, p_code text, p_data jsonb, p_org text) returns text language plpgsql security definer set search_path = public as $$
declare who text;
begin
  perform trip_throttle();
  if org_owner_match(p_org) then who := 'Owner';
  else select name into who from trip_organizers where lower(code) = lower(trim(coalesce(p_org,'')));
  end if;
  if who is null then perform trip_fail(); return 'not-organizer'; end if;
  if p_trip !~ '^[a-z0-9-]{8,64}$' then return 'bad-id'; end if;
  if length(trim(coalesce(p_code,''))) < 8 or trim(p_code) !~ '[0-9]' then return 'too-weak'; end if;
  if exists (select 1 from trip_passcodes where lower(trim(passcode)) = lower(trim(p_code))) then return 'taken'; end if;
  insert into trip_passcodes (trip_id, passcode) values (p_trip, upper(trim(p_code)));
  insert into trip_items (trip_id, id, kind, data) values (p_trip, 'trip:main', 'trip', coalesce(p_data, '{}'::jsonb) || jsonb_build_object('startedBy', who));
  return 'ok';
end $$;

revoke all on function public.org_owner_match(text) from public, anon, authenticated;
revoke all on function public.org_is_owner(text) from public;
revoke all on function public.org_list(text) from public;
revoke all on function public.org_add(text,text,text) from public;
revoke all on function public.org_remove(text,text) from public;
grant execute on function public.org_is_owner(text) to anon, authenticated;
grant execute on function public.org_list(text) to anon, authenticated;
grant execute on function public.org_add(text,text,text) to anon, authenticated;
grant execute on function public.org_remove(text,text) to anon, authenticated;
grant execute on function public.trip_create(text,text,jsonb,text) to anon, authenticated;

notify pgrst, 'reload schema';
