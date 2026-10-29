-- Trip Book: banner photos. Run once in Supabase (birdie book) > SQL Editor > New query > Run.
-- Photos are fetched separately so the every-few-seconds refresh stays small.

create or replace function public.trip_load(p_trip text, p_code text) returns setof public.trip_items language plpgsql security definer set search_path = public as $$
begin
  perform trip_throttle();
  if not trip_code_match(p_trip, p_code) then
    perform trip_fail();
    return query select p_trip, 'error:passcode'::text, 'error'::text, '{}'::jsonb, now();
    return;
  end if;
  return query select * from trip_items where trip_id = p_trip and kind <> 'banner';
end $$;

create or replace function public.trip_banner(p_trip text, p_code text) returns jsonb language plpgsql security definer set search_path = public as $$
begin
  perform trip_throttle();
  if not trip_code_match(p_trip, p_code) then perform trip_fail(); return null; end if;
  return (select data from trip_items where trip_id = p_trip and id = 'banner:main');
end $$;

revoke all on function public.trip_banner(text,text) from public;
grant execute on function public.trip_banner(text,text) to anon, authenticated;
notify pgrst, 'reload schema';
