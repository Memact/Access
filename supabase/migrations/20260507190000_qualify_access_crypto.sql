create schema if not exists extensions;
create extension if not exists pgcrypto with schema extensions;

create or replace function public.memact_create_api_key(app_id_input uuid, key_name_input text default 'Default app key', scopes_input text[] default array[]::text[])
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  current_user_id uuid := public.memact_require_authenticated_user();
  target_app public.memact_apps%rowtype;
  created_key public.memact_api_keys%rowtype;
  raw_key text := 'mka_' || encode(gen_random_bytes(24), 'hex');
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

create or replace function public.memact_verify_api_key(api_key_input text, required_scopes_input text[] default array[]::text[])
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  target_key public.memact_api_keys%rowtype;
  target_app public.memact_apps%rowtype;
  target_consent public.memact_consents%rowtype;
  effective_scopes text[];
  allowed boolean;
begin
  select *
  into target_key
  from public.memact_api_keys key
  where key.key_hash = encode(digest(coalesce(api_key_input, ''), 'sha256'), 'hex')
    and key.revoked_at is null;

  if not found then
    return jsonb_build_object(
      'allowed', false,
      'error', jsonb_build_object(
        'code', 'invalid_api_key',
        'message', 'API key is invalid or revoked.'
      )
    );
  end if;

  select *
  into target_app
  from public.memact_apps app
  where app.id = target_key.app_id
    and app.revoked_at is null;

  if not found then
    return jsonb_build_object(
      'allowed', false,
      'error', jsonb_build_object(
        'code', 'app_revoked',
        'message', 'App is missing or revoked.'
      )
    );
  end if;

  select *
  into target_consent
  from public.memact_consents consent
  where consent.user_id = target_key.owner_user_id
    and consent.app_id = target_key.app_id
    and consent.revoked_at is null;

  if not found then
    return jsonb_build_object(
      'allowed', false,
      'error', jsonb_build_object(
        'code', 'consent_missing',
        'message', 'User permissions are missing for this app.'
      )
    );
  end if;

  select array(
    select scope
    from unnest(target_key.scopes) scope
    where scope = any(target_consent.scopes)
  )
  into effective_scopes;

  allowed := required_scopes_input <@ effective_scopes;

  if allowed then
    update public.memact_api_keys
    set last_used_at = timezone('utc', now())
    where id = target_key.id;
  end if;

  return jsonb_build_object(
    'allowed', allowed,
    'app', jsonb_build_object(
      'id', target_app.id,
      'name', target_app.name,
      'slug', target_app.slug
    ),
    'key', jsonb_build_object(
      'id', target_key.id,
      'key_prefix', target_key.key_prefix,
      'scopes', to_jsonb(target_key.scopes)
    ),
    'scopes', to_jsonb(effective_scopes),
    'missing_scopes', to_jsonb(array(
      select scope
      from unnest(required_scopes_input) scope
      where not scope = any(effective_scopes)
    )),
    'error', case when allowed then null else jsonb_build_object(
      'code', 'scope_denied',
      'message', 'API key or user permissions do not include the requested scopes.'
    ) end
  );
end;
$$;

grant execute on function public.memact_create_api_key(uuid, text, text[]) to authenticated;
grant execute on function public.memact_verify_api_key(text, text[]) to anon, authenticated;
