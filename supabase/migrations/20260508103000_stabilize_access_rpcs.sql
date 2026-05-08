create schema if not exists extensions;
do $$
begin
  if exists (select 1 from pg_extension where extname = 'pgcrypto') then
    alter extension pgcrypto set schema extensions;
  else
    create extension pgcrypto with schema extensions;
  end if;
end $$;

alter table public.memact_api_keys
  drop column if exists categories;

drop function if exists public.memact_create_app(text, text, jsonb);
drop function if exists public.memact_create_app(text, text, jsonb, text, text[]);
drop function if exists public.memact_create_app(text, text, text[]);
drop function if exists public.memact_create_app(text, text, text[], text);
drop function if exists public.memact_create_app(text, text, text[], text, text[]);
drop function if exists public.memact_create_app(text[], text, text, text, text[]);
create or replace function public.memact_create_app(
  app_name text,
  app_description text default '',
  app_redirect_urls jsonb default '[]'::jsonb,
  app_developer_url text default '',
  app_categories text[] default array['web:news','web:research','media:video','ai:assistant','dev:code']::text[]
)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  current_user_id uuid := public.memact_require_authenticated_user();
  cleaned_name text := left(trim(coalesce(app_name, '')), 80);
  normalized_slug text := public.memact_normalize_app_name(app_name);
  clean_categories text[] := public.memact_clean_allowed_values(app_categories, public.memact_known_categories());
  created_app public.memact_apps%rowtype;
begin
  if char_length(cleaned_name) < 2 then
    raise exception 'App name must be at least 2 characters.';
  end if;
  if normalized_slug = '' then
    raise exception 'App name needs letters or numbers.';
  end if;
  if array_length(clean_categories, 1) is null then
    raise exception 'At least one activity category is required.';
  end if;
  if exists (
    select 1
    from public.memact_apps app
    where app.owner_user_id = current_user_id
      and app.revoked_at is null
      and app.slug = normalized_slug
  ) then
    raise exception 'You already have an app with this name.';
  end if;

  insert into public.memact_apps (
    owner_user_id,
    name,
    slug,
    description,
    developer_url,
    redirect_urls,
    default_categories
  )
  values (
    current_user_id,
    cleaned_name,
    normalized_slug,
    left(trim(coalesce(app_description, '')), 240),
    left(trim(coalesce(app_developer_url, '')), 300),
    case
      when jsonb_typeof(coalesce(app_redirect_urls, '[]'::jsonb)) = 'array' then coalesce(app_redirect_urls, '[]'::jsonb)
      else '[]'::jsonb
    end,
    clean_categories
  )
  returning * into created_app;

  perform public.memact_audit(current_user_id, 'app.create', jsonb_build_object(
    'app_id', created_app.id,
    'categories', to_jsonb(clean_categories)
  ));

  return jsonb_build_object('app', jsonb_build_object(
    'id', created_app.id,
    'owner_user_id', created_app.owner_user_id,
    'name', created_app.name,
    'slug', created_app.slug,
    'description', created_app.description,
    'developer_url', created_app.developer_url,
    'redirect_urls', created_app.redirect_urls,
    'default_scopes', to_jsonb(created_app.default_scopes),
    'default_categories', to_jsonb(created_app.default_categories),
    'created_at', created_app.created_at,
    'revoked_at', created_app.revoked_at
  ));
end;
$$;

drop function if exists public.memact_grant_consent(uuid, text[]);
drop function if exists public.memact_grant_consent(uuid, text[], text[]);
create or replace function public.memact_grant_consent(
  app_id_input uuid,
  scopes_input text[],
  categories_input text[] default array['web:news','web:research','media:video','ai:assistant','dev:code']::text[]
)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  current_user_id uuid := public.memact_require_authenticated_user();
  clean_scopes text[] := public.memact_clean_allowed_values(scopes_input, public.memact_known_scopes());
  clean_categories text[] := public.memact_clean_allowed_values(categories_input, public.memact_known_categories());
  target_app public.memact_apps%rowtype;
  target_consent public.memact_consents%rowtype;
begin
  select * into target_app
  from public.memact_apps app
  where app.id = app_id_input
    and app.revoked_at is null;
  if not found then raise exception 'App not found.'; end if;
  if array_length(clean_scopes, 1) is null then raise exception 'At least one scope is required.'; end if;
  if array_length(clean_categories, 1) is null then raise exception 'At least one activity category is required.'; end if;
  if not clean_categories <@ target_app.default_categories then
    raise exception 'This app is not registered for one or more selected activity categories.';
  end if;

  select * into target_consent
  from public.memact_consents consent
  where consent.user_id = current_user_id
    and consent.app_id = target_app.id
    and consent.revoked_at is null;

  if found then
    update public.memact_consents
    set scopes = clean_scopes,
        categories = clean_categories,
        updated_at = timezone('utc', now())
    where id = target_consent.id
    returning * into target_consent;
  else
    insert into public.memact_consents (user_id, app_id, scopes, categories)
    values (current_user_id, target_app.id, clean_scopes, clean_categories)
    returning * into target_consent;
  end if;

  perform public.memact_audit(current_user_id, 'consent.grant_or_update', jsonb_build_object(
    'app_id', target_app.id,
    'scopes', to_jsonb(clean_scopes),
    'categories', to_jsonb(clean_categories)
  ));

  return jsonb_build_object('consent', jsonb_build_object(
    'id', target_consent.id,
    'user_id', target_consent.user_id,
    'app_id', target_consent.app_id,
    'scopes', to_jsonb(target_consent.scopes),
    'categories', to_jsonb(target_consent.categories),
    'created_at', target_consent.created_at,
    'updated_at', target_consent.updated_at,
    'revoked_at', target_consent.revoked_at
  ));
end;
$$;

drop function if exists public.memact_connect_app(uuid, text[], text[]);
create or replace function public.memact_connect_app(
  app_id_input uuid,
  scopes_input text[],
  categories_input text[] default array[]::text[]
)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  app_info jsonb;
  requested_scopes text[];
  requested_categories text[];
  granted jsonb;
begin
  app_info := public.memact_get_connect_app(app_id_input, scopes_input, categories_input);
  select array_agg(value) into requested_scopes
  from jsonb_array_elements_text(app_info->'requested_scopes') value;
  select array_agg(value) into requested_categories
  from jsonb_array_elements_text(app_info->'requested_categories') value;
  granted := public.memact_grant_consent(app_id_input, requested_scopes, requested_categories);
  return granted || jsonb_build_object('connected', true);
end;
$$;

drop function if exists public.memact_create_api_key(uuid, text, text[]);
drop function if exists public.memact_create_api_key(uuid, text, text[], text[]);
create or replace function public.memact_create_api_key(
  app_id_input uuid,
  key_name_input text default 'Default app key',
  scopes_input text[] default array[]::text[]
)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  current_user_id uuid := public.memact_require_authenticated_user();
  target_app public.memact_apps%rowtype;
  created_key public.memact_api_keys%rowtype;
  clean_scopes text[] := public.memact_clean_allowed_values(scopes_input, public.memact_known_scopes());
  raw_key text := 'mka_' || substring(
    encode(
      extensions.digest(
        extensions.gen_random_uuid()::text || ':' || extensions.gen_random_uuid()::text || ':' || clock_timestamp()::text || ':' || random()::text,
        'sha256'
      ),
      'hex'
    )
    from 1 for 48
  );
begin
  select * into target_app
  from public.memact_apps app
  where app.id = app_id_input
    and app.owner_user_id = current_user_id
    and app.revoked_at is null;
  if not found then raise exception 'App not found.'; end if;
  if array_length(clean_scopes, 1) is null then raise exception 'At least one valid scope is required.'; end if;

  insert into public.memact_api_keys (app_id, owner_user_id, name, key_hash, key_prefix, scopes)
  values (
    target_app.id,
    current_user_id,
    left(trim(coalesce(key_name_input, 'Default app key')), 80),
    encode(extensions.digest(raw_key::text, 'sha256'::text), 'hex'),
    left(raw_key, 12),
    clean_scopes
  )
  returning * into created_key;

  perform public.memact_audit(current_user_id, 'api_key.create', jsonb_build_object(
    'app_id', target_app.id,
    'key_id', created_key.id,
    'scopes', to_jsonb(clean_scopes)
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

grant execute on function public.memact_create_app(text, text, jsonb, text, text[]) to authenticated;
grant execute on function public.memact_grant_consent(uuid, text[], text[]) to authenticated;
grant execute on function public.memact_connect_app(uuid, text[], text[]) to authenticated;
grant execute on function public.memact_create_api_key(uuid, text, text[]) to authenticated;

notify pgrst, 'reload schema';
