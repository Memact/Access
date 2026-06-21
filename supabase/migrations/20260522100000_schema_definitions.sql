do $$
begin
  if exists (select 1 from pg_extension where extname = 'pgcrypto') then
    alter extension pgcrypto set schema extensions;
  else
    create extension pgcrypto with schema extensions;
  end if;
end
$$;

notify pgrst, 'reload schema';

