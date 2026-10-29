-- Trip Book: multiple trips, each with its own passcode.
-- Run once in Supabase (birdie book) > SQL Editor > New query > Run.
-- Your Vegas trip and its passcode stay exactly as they are.

-- No two trips can share a passcode (capital letters don't matter).
create unique index if not exists trip_passcodes_code_uniq
  on public.trip_passcodes (lower(trim(passcode)));

-- Join: turn a passcode into its trip (nothing is returned for a wrong passcode).
create or replace function public.trip_find(p_code text)
returns text language sql stable security definer set search_path = public as $$
  select trip_id from trip_passcodes
  where length(trim(coalesce(p_code,''))) >= 6
    and lower(trim(passcode)) = lower(trim(p_code))
  limit 1;
$$;

-- New trip: create it with its own passcode and starting details.
create or replace function public.trip_create(p_trip text, p_code text, p_data jsonb)
returns text language plpgsql security definer set search_path = public as $$
begin
  if p_trip !~ '^[a-z0-9-]{8,64}$' then raise exception 'bad trip id' using errcode = '22023'; end if;
  if length(trim(coalesce(p_code,''))) < 6 then raise exception 'passcode too short' using errcode = '22023'; end if;
  if exists (select 1 from trip_passcodes where lower(trim(passcode)) = lower(trim(p_code))) then
    raise exception 'passcode taken' using errcode = '23505';
  end if;
  insert into trip_passcodes (trip_id, passcode) values (p_trip, upper(trim(p_code)));
  insert into trip_items (trip_id, id, kind, data) values (p_trip, 'trip:main', 'trip', coalesce(p_data, '{}'::jsonb));
  return p_trip;
end $$;

revoke all on function public.trip_find(text) from public;
revoke all on function public.trip_create(text,text,jsonb) from public;
grant execute on function public.trip_find(text) to anon, authenticated;
grant execute on function public.trip_create(text,text,jsonb) to anon, authenticated;

notify pgrst, 'reload schema';
