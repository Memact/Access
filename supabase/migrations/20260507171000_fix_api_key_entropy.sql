create or replace function public.memact_create_api_key(app_id_input uuid, key_name_input text default 'Default app key', scopes_input text[] default array[]::text[])
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  current_user_id uuid := public.memact_require_authenticated_user();
  target_app public.memact_apps%rowtype;
  created_key public.memact_api_keys%rowtype;
  raw_key text := 'mka_' || substring(
    encode(
      digest(
        gen_random_uuid()::text || ':' || gen_random_uuid()::text || ':' || clock_timestamp()::text || ':' || random()::text,
        'sha256'
      ),
      'hex'
    )
    from 1 for 48
  );
begin
  select *
  into target_app
  from public.memact_apps app
  where app.id = app_id_input
    and app.owner_user_id = current_user_id
    and app.revoked_at is null;

  if not found then
    raise exception 'App not found.';
  end if;

  insert into public.memact_api_keys (
    app_id,
    owner_user_id,
    name,
    key_hash,
    key_prefix,
    scopes
  )
  values (
    target_app.id,
    current_user_id,
    left(trim(coalesce(key_name_input, 'Default app key')), 80),
    encode(digest(raw_key, 'sha256'), 'hex'),
    left(raw_key, 12),
    coalesce(scopes_input, array[]::text[])
  )
  returning * into created_key;

  perform public.memact_audit(current_user_id, 'api_key.create', jsonb_build_object(
    'app_id', target_app.id,
    'key_id', created_key.id,
    'scopes', to_jsonb(created_key.scopes)
  ));

  return jsonb_build_object(
    'api_key', jsonb_build_object(
      'id', created_key.id,
      'app_id', created_key.app_id,
      'owner_user_id', created_key.owner_user_id,
      'name', created_key.name,
      'key_prefix', created_key.key_prefix,
      'scopes', to_jsonb(created_key.scopes),
      'created_at', created_key.created_at,
      'last_used_at', created_key.last_used_at,
      'revoked_at', created_key.revoked_at
    ),
    'key', raw_key
  );
end;
$$;
