-- Vegas Girls Trip: switch to passcode sign-in (no emails).
-- Run once in Supabase (birdie book project) > SQL Editor > New query > Run.
-- 1) CHANGE THE PASSCODE on the line marked below before you click Run.

-- Private table that holds the trip passcode. Nobody can read it from the app.
create table if not exists public.trip_passcodes (
  trip_id  text primary key,
  passcode text not null
);
alter table public.trip_passcodes enable row level security;
revoke all on public.trip_passcodes from anon, authenticated;

insert into public.trip_passcodes (trip_id, passcode)
values ('vegas-girls-trip', 'CHANGE-ME')          -- <<< put your passcode here
on conflict (trip_id) do update set passcode = excluded.passcode;

-- Lock the trip table: the app now goes through the passcode-checked functions below.
drop policy if exists "signed in can read"   on public.trip_items;
drop policy if exists "signed in can add"    on public.trip_items;
drop policy if exists "signed in can edit"   on public.trip_items;
drop policy if exists "signed in can delete" on public.trip_items;
revoke all on public.trip_items from anon, authenticated;

create or replace function public.trip_code_ok(p_trip text, p_code text)
returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from trip_passcodes
                 where trip_id = p_trip and lower(trim(passcode)) = lower(trim(coalesce(p_code,''))));
$$;

create or replace function public.trip_load(p_trip text, p_code text)
returns setof public.trip_items language plpgsql stable security definer set search_path = public as $$
begin
  if not trip_code_ok(p_trip, p_code) then raise exception 'wrong passcode' using errcode = '28P01'; end if;
  return query select * from trip_items where trip_id = p_trip;
end $$;

create or replace function public.trip_save(p_trip text, p_code text, p_id text, p_kind text, p_data jsonb)
returns void language plpgsql security definer set search_path = public as $$
begin
  if not trip_code_ok(p_trip, p_code) then raise exception 'wrong passcode' using errcode = '28P01'; end if;
  insert into trip_items (trip_id, id, kind, data, updated_at) values (p_trip, p_id, p_kind, p_data, now())
  on conflict (trip_id, id) do update set kind = excluded.kind, data = excluded.data, updated_at = now();
end $$;

create or replace function public.trip_delete(p_trip text, p_code text, p_id text)
returns void language plpgsql security definer set search_path = public as $$
begin
  if not trip_code_ok(p_trip, p_code) then raise exception 'wrong passcode' using errcode = '28P01'; end if;
  delete from trip_items where trip_id = p_trip and id = p_id;
end $$;

revoke all on function public.trip_code_ok(text,text) from public;
grant execute on function public.trip_code_ok(text,text)                   to anon, authenticated;
grant execute on function public.trip_load(text,text)                      to anon, authenticated;
grant execute on function public.trip_save(text,text,text,text,jsonb)      to anon, authenticated;
grant execute on function public.trip_delete(text,text,text)               to anon, authenticated;
