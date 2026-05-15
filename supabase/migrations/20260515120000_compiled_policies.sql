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

drop function if exists public.memact_create_app(text, text, text[]);
drop function if exists public.memact_create_app(text, text, text[], text);
drop function if exists public.memact_create_app(text, text, text[], text, text[]);
drop function if exists public.memact_create_app(text[], text, text, text, text[]);

alter table public.memact_apps
  add column if not exists compiled_policy jsonb;

alter table public.memact_consents
  add column if not exists compiled_policy jsonb;

create or replace function public.memact_compile_policy(app_id_input uuid, scopes_input text[] default array[]::text[], categories_input text[] default array[]::text[], app_purpose text default '')
returns jsonb
language sql
stable
security definer
set search_path = public, extensions
as $$
  with clean as (
    select
      public.memact_clean_allowed_values(scopes_input, public.memact_known_scopes()) as scopes,
      public.memact_clean_allowed_values(categories_input, public.memact_known_categories()) as categories,
      left(trim(coalesce(app_purpose, '')), 240) as purpose
  ),
  warnings as (
    select coalesce(jsonb_agg(warning), '[]'::jsonb) as value
    from (
      select scope || ' is risky for ' || category || '; explain why users need it.' as warning
      from clean, unnest(clean.scopes) scope, unnest(clean.categories) category
      where scope in ('memory:read_graph', 'capture:device')
      union all
      select 'Broad permissions need a clear app purpose.' as warning
      from clean
      where array_length(clean.scopes, 1) > 5 and char_length(clean.purpose) < 12
    ) warnings
  )
  select jsonb_build_object(
    'id', 'policy_' || substr(encode(extensions.digest(coalesce(app_id_input::text, '') || '__' || array_to_string((select scopes from clean), '+') || '__' || array_to_string((select categories from clean), '+') || '__' || (select purpose from clean), 'sha256'), 'hex'), 1, 12),
    'app_id', app_id_input,
    'product', 'permissioned_understanding',
    'tagline', 'Understand users'' digital activity.',
    'purpose', (select purpose from clean),
    'scopes', to_jsonb((select scopes from clean)),
    'categories', to_jsonb((select categories from clean)),
    'strategy', public.memact_understanding_strategy((select scopes from clean), (select categories from clean)),
    'warnings', (select value from warnings),
    'storage', jsonb_build_object(
      'default', jsonb_build_object('id', 'local-first-memory', 'label', 'Local-first memory'),
      'future_user_cloud', jsonb_build_object('id', 'user-owned-cloud-memory', 'label', 'User-owned cloud memory', 'status', 'planned', 'purpose', 'cross-platform sync to user-owned storage')
    )
  )
$$;

create or replace function public.memact_set_app_compiled_policy()
returns trigger
language plpgsql
security definer
set search_path = public, extensions
as $$
begin
  new.compiled_policy := public.memact_compile_policy(new.id, array[]::text[], new.default_categories, coalesce(new.description, new.name));
  return new;
end;
$$;

drop trigger if exists memact_apps_compile_policy on public.memact_apps;
create trigger memact_apps_compile_policy
before insert or update of default_categories, description, name
on public.memact_apps
for each row
execute function public.memact_set_app_compiled_policy();

create or replace function public.memact_set_consent_compiled_policy()
returns trigger
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  target_app public.memact_apps%rowtype;
begin
  select * into target_app from public.memact_apps app where app.id = new.app_id;
  new.compiled_policy := public.memact_compile_policy(new.app_id, new.scopes, new.categories, coalesce(target_app.description, target_app.name));
  return new;
end;
$$;

drop trigger if exists memact_consents_compile_policy on public.memact_consents;
create trigger memact_consents_compile_policy
before insert or update of scopes, categories
on public.memact_consents
for each row
execute function public.memact_set_consent_compiled_policy();

update public.memact_apps app
set compiled_policy = public.memact_compile_policy(app.id, array[]::text[], app.default_categories, coalesce(app.description, app.name))
where app.compiled_policy is null;

update public.memact_consents consent
set compiled_policy = public.memact_compile_policy(consent.app_id, consent.scopes, consent.categories, coalesce(app.description, app.name))
from public.memact_apps app
where app.id = consent.app_id
  and consent.compiled_policy is null;

drop function if exists public.memact_verify_api_key(text, text[]);
drop function if exists public.memact_verify_api_key(text, text[], text[]);
drop function if exists public.memact_verify_api_key(text, text[], text[], uuid);
create or replace function public.memact_verify_api_key(api_key_input text, required_scopes_input text[] default array[]::text[], activity_categories_input text[] default array[]::text[], consent_id_input uuid default null)
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
  effective_categories text[];
  compiled jsonb;
  clean_required_scopes text[] := public.memact_clean_allowed_values(required_scopes_input, public.memact_known_scopes());
  clean_required_categories text[] := public.memact_clean_allowed_values(activity_categories_input, public.memact_known_categories());
  allowed boolean;
begin
  select * into target_key
  from public.memact_api_keys key
  where key.key_hash = encode(extensions.digest(coalesce(api_key_input, '')::text, 'sha256'::text), 'hex')
    and key.revoked_at is null;
  if not found then return jsonb_build_object('allowed', false, 'error', jsonb_build_object('code', 'invalid_api_key', 'message', 'API key is invalid or revoked.')); end if;

  select * into target_app
  from public.memact_apps app
  where app.id = target_key.app_id
    and app.revoked_at is null;
  if not found then return jsonb_build_object('allowed', false, 'error', jsonb_build_object('code', 'app_revoked', 'message', 'App is missing or revoked.')); end if;

  select * into target_consent
  from public.memact_consents consent
  where consent.app_id = target_key.app_id
    and consent.revoked_at is null
    and (
      (consent_id_input is not null and consent.id = consent_id_input)
      or (consent_id_input is null and consent.user_id = target_key.owner_user_id)
    )
  order by consent.updated_at desc
  limit 1;
  if not found then return jsonb_build_object('allowed', false, 'error', jsonb_build_object('code', 'consent_missing', 'message', 'User permissions are missing for this app.')); end if;

  select coalesce(array_agg(scope), array[]::text[]) into effective_scopes
  from unnest(target_key.scopes) scope
  where scope = any(target_consent.scopes);

  effective_categories := public.memact_clean_allowed_values(target_consent.categories, public.memact_known_categories());
  compiled := public.memact_compile_policy(target_app.id, effective_scopes, effective_categories, coalesce(target_app.description, target_app.name));

  allowed := clean_required_scopes <@ effective_scopes and clean_required_categories <@ effective_categories;
  if allowed then
    update public.memact_api_keys set last_used_at = timezone('utc', now()) where id = target_key.id;
    update public.memact_consents set compiled_policy = compiled, updated_at = timezone('utc', now()) where id = target_consent.id;
  end if;

  return jsonb_build_object(
    'allowed', allowed,
    'user_id', target_consent.user_id,
    'connection_id', target_consent.id,
    'app', jsonb_build_object('id', target_app.id, 'name', target_app.name, 'slug', target_app.slug, 'developer_url', target_app.developer_url),
    'key', jsonb_build_object('id', target_key.id, 'key_prefix', target_key.key_prefix, 'scopes', to_jsonb(target_key.scopes)),
    'scopes', to_jsonb(effective_scopes),
    'categories', to_jsonb(effective_categories),
    'compiled_policy', compiled,
    'understanding_strategy', compiled->'strategy',
    'missing_scopes', to_jsonb(array(select scope from unnest(clean_required_scopes) scope where not scope = any(effective_scopes))),
    'missing_categories', to_jsonb(array(select category from unnest(clean_required_categories) category where not category = any(effective_categories))),
    'policy', jsonb_build_object('plan', 'free_unlimited', 'graph_read_allowed', 'memory:read_graph' = any(effective_scopes)),
    'error', case when allowed then null else jsonb_build_object('code', 'scope_or_category_denied', 'message', 'API key scope or app permission does not include the requested access.') end
  );
end;
$$;

grant execute on function public.memact_compile_policy(uuid, text[], text[], text) to anon, authenticated;
grant execute on function public.memact_verify_api_key(text, text[], text[], uuid) to anon, authenticated;

notify pgrst, 'reload schema';
