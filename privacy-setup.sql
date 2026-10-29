-- Trip Book privacy: organizer code for new trips + lockout after too many wrong passcodes.
-- Run once in Supabase (birdie book) > SQL Editor > New query.
-- 1) Change ORGANIZER-CODE-HERE below to your own organizer code, then click Run.

create table if not exists public.app_settings (key text primary key, value text not null);
alter table public.app_settings enable row level security;
revoke all on public.app_settings from anon, authenticated;
insert into public.app_settings (key, value) values ('organizer_code', 'ORGANIZER-CODE-HERE')   -- <<< your organizer code
on conflict (key) do update set value = excluded.value;

create table if not exists public.trip_attempts (who text not null, at timestamptz not null default now());
alter table public.trip_attempts enable row level security;
revoke all on public.trip_attempts from anon, authenticated;
create index if not exists trip_attempts_who_at on public.trip_attempts (who, at);

-- Which device is asking (by internet address).
create or replace function public.trip_client() returns text language sql stable set search_path = public as $$
  select coalesce(nullif(trim(split_part(coalesce(nullif(current_setting('request.headers', true), ''), '{}')::json->>'x-forwarded-for', ',', 1)), ''), 'unknown');
$$;
-- Block a device after 20 wrong tries in 15 minutes.
create or replace function public.trip_throttle() returns void language plpgsql security definer set search_path = public as $$
begin
  if (select count(*) from trip_attempts where who = trip_client() and at > now() - interval '15 minutes') >= 20 then
    raise exception 'too many tries' using errcode = 'P0001';
  end if;
end $$;
create or replace function public.trip_fail() returns void language plpgsql security definer set search_path = public as $$
begin
  delete from trip_attempts where at < now() - interval '1 day';
  insert into trip_attempts (who) values (trip_client());
end $$;
create or replace function public.trip_code_match(p_trip text, p_code text) returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from trip_passcodes where trip_id = p_trip and lower(trim(passcode)) = lower(trim(coalesce(p_code,''))));
$$;

-- Replace the app's functions with versions that count wrong tries.
drop function if exists public.trip_code_ok(text,text);
drop function if exists public.trip_load(text,text);
drop function if exists public.trip_save(text,text,text,text,jsonb);
drop function if exists public.trip_delete(text,text,text);
drop function if exists public.trip_find(text);
drop function if exists public.trip_create(text,text,jsonb);

create function public.trip_code_ok(p_trip text, p_code text) returns boolean language plpgsql security definer set search_path = public as $$
begin
  perform trip_throttle();
  if trip_code_match(p_trip, p_code) then return true; end if;
  perform trip_fail(); return false;
end $$;

create function public.trip_load(p_trip text, p_code text) returns setof public.trip_items language plpgsql security definer set search_path = public as $$
begin
  perform trip_throttle();
  if not trip_code_match(p_trip, p_code) then
    perform trip_fail();
    return query select p_trip, 'error:passcode'::text, 'error'::text, '{}'::jsonb, now();
    return;
  end if;
  return query select * from trip_items where trip_id = p_trip;
end $$;

create function public.trip_save(p_trip text, p_code text, p_id text, p_kind text, p_data jsonb) returns text language plpgsql security definer set search_path = public as $$
begin
  perform trip_throttle();
  if not trip_code_match(p_trip, p_code) then perform trip_fail(); return 'bad-passcode'; end if;
  insert into trip_items (trip_id, id, kind, data, updated_at) values (p_trip, p_id, p_kind, p_data, now())
  on conflict (trip_id, id) do update set kind = excluded.kind, data = excluded.data, updated_at = now();
  return 'ok';
end $$;

create function public.trip_delete(p_trip text, p_code text, p_id text) returns text language plpgsql security definer set search_path = public as $$
begin
  perform trip_throttle();
  if not trip_code_match(p_trip, p_code) then perform trip_fail(); return 'bad-passcode'; end if;
  delete from trip_items where trip_id = p_trip and id = p_id;
  return 'ok';
end $$;

create function public.trip_find(p_code text) returns text language plpgsql security definer set search_path = public as $$
declare t text;
begin
  perform trip_throttle();
  select trip_id into t from trip_passcodes
   where length(trim(coalesce(p_code,''))) >= 6 and lower(trim(passcode)) = lower(trim(p_code)) limit 1;
  if t is null then perform trip_fail(); end if;
  return t;
end $$;

create function public.trip_create(p_trip text, p_code text, p_data jsonb, p_org text) returns text language plpgsql security definer set search_path = public as $$
begin
  perform trip_throttle();
  if not exists (select 1 from app_settings where key = 'organizer_code' and lower(trim(value)) = lower(trim(coalesce(p_org,'')))) then
    perform trip_fail(); return 'not-organizer';
  end if;
  if p_trip !~ '^[a-z0-9-]{8,64}$' then return 'bad-id'; end if;
  if length(trim(coalesce(p_code,''))) < 8 or trim(p_code) !~ '[0-9]' then return 'too-weak'; end if;
  if exists (select 1 from trip_passcodes where lower(trim(passcode)) = lower(trim(p_code))) then return 'taken'; end if;
  insert into trip_passcodes (trip_id, passcode) values (p_trip, upper(trim(p_code)));
  insert into trip_items (trip_id, id, kind, data) values (p_trip, 'trip:main', 'trip', coalesce(p_data, '{}'::jsonb));
  return 'ok';
end $$;

revoke all on function public.trip_client() from public, anon, authenticated;
revoke all on function public.trip_throttle() from public, anon, authenticated;
revoke all on function public.trip_fail() from public, anon, authenticated;
revoke all on function public.trip_code_match(text,text) from public, anon, authenticated;
revoke all on function public.trip_code_ok(text,text) from public;
revoke all on function public.trip_load(text,text) from public;
revoke all on function public.trip_save(text,text,text,text,jsonb) from public;
revoke all on function public.trip_delete(text,text,text) from public;
revoke all on function public.trip_find(text) from public;
revoke all on function public.trip_create(text,text,jsonb,text) from public;
grant execute on function public.trip_code_ok(text,text) to anon, authenticated;
grant execute on function public.trip_load(text,text) to anon, authenticated;
grant execute on function public.trip_save(text,text,text,text,jsonb) to anon, authenticated;
grant execute on function public.trip_delete(text,text,text) to anon, authenticated;
grant execute on function public.trip_find(text) to anon, authenticated;
grant execute on function public.trip_create(text,text,jsonb,text) to anon, authenticated;

notify pgrst, 'reload schema';
