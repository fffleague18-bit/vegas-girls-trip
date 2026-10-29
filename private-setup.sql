-- Splitzy: private "Just me" expenses. Run once in Supabase (birdie book) > SQL Editor > New query > Run.
-- Each phone holds a secret private code; the database only keeps a scrambled version of it,
-- so nobody else on the trip (owner included) can read someone's private list through the app.

create table if not exists public.trip_private (
  trip_id    text not null,
  owner      text not null,
  id         text not null,
  data       jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now(),
  primary key (trip_id, owner, id)
);
alter table public.trip_private enable row level security;
revoke all on public.trip_private from anon, authenticated;

create or replace function public.mine_load(p_trip text, p_code text, p_key text) returns table(id text, data jsonb) language plpgsql security definer set search_path = public as $$
begin
  perform trip_throttle();
  if not trip_code_match(p_trip, p_code) or length(coalesce(p_key,'')) < 20 then perform trip_fail(); return; end if;
  return query select t.id, t.data from trip_private t where t.trip_id = p_trip and t.owner = md5(p_key);
end $$;

create or replace function public.mine_save(p_trip text, p_code text, p_key text, p_id text, p_data jsonb) returns text language plpgsql security definer set search_path = public as $$
begin
  perform trip_throttle();
  if not trip_code_match(p_trip, p_code) or length(coalesce(p_key,'')) < 20 then perform trip_fail(); return 'bad-passcode'; end if;
  insert into trip_private (trip_id, owner, id, data, updated_at) values (p_trip, md5(p_key), p_id, p_data, now())
  on conflict (trip_id, owner, id) do update set data = excluded.data, updated_at = now();
  return 'ok';
end $$;

create or replace function public.mine_delete(p_trip text, p_code text, p_key text, p_id text) returns text language plpgsql security definer set search_path = public as $$
begin
  perform trip_throttle();
  if not trip_code_match(p_trip, p_code) or length(coalesce(p_key,'')) < 20 then perform trip_fail(); return 'bad-passcode'; end if;
  delete from trip_private where trip_id = p_trip and owner = md5(p_key) and id = p_id;
  return 'ok';
end $$;

revoke all on function public.mine_load(text,text,text) from public;
revoke all on function public.mine_save(text,text,text,text,jsonb) from public;
revoke all on function public.mine_delete(text,text,text,text) from public;
grant execute on function public.mine_load(text,text,text) to anon, authenticated;
grant execute on function public.mine_save(text,text,text,text,jsonb) to anon, authenticated;
grant execute on function public.mine_delete(text,text,text,text) to anon, authenticated;
notify pgrst, 'reload schema';
