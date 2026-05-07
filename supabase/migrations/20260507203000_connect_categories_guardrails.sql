create schema if not exists extensions;
create extension if not exists pgcrypto with schema extensions;

alter table public.memact_apps
  add column if not exists developer_url text not null default '',
  add column if not exists default_categories text[] not null default array[
    'web:news',
    'web:research',
    'media:video',
    'ai:assistant',
    'dev:code'
  ]::text[];

alter table public.memact_consents
  add column if not exists categories text[] not null default array[
    'web:news',
    'web:research',
    'media:video',
    'ai:assistant',
    'dev:code'
  ]::text[];

alter table public.memact_api_keys
  drop column if exists categories;

create or replace function public.memact_known_categories()
returns text[]
language sql
immutable
as $$
  select array[
    'web:news',
    'web:research',
    'web:commerce',
    'web:social',
    'media:video',
    'media:audio',
    'ai:assistant',
    'dev:code',
    'work:docs'
  ]::text[];
$$;

create or replace function public.memact_known_scopes()
returns text[]
language sql
immutable
as $$
  select array[
    'capture:webpage',
    'capture:media',
    'capture:device',
    'schema:write',
    'graph:write',
    'memory:write',
    'memory:read_summary',
    'memory:read_evidence',
    'memory:read_graph'
  ]::text[];
$$;

create or replace function public.memact_clean_allowed_values(input_values text[], allowed_values text[])
returns text[]
language sql
immutable
as $$
  select coalesce(array_agg(distinct value order by value), array[]::text[])
  from unnest(coalesce(input_values, array[]::text[])) value
  where value = any(allowed_values);
$$;

drop function if exists public.memact_policy();
create or replace function public.memact_policy()
returns jsonb
language sql
stable
security definer
set search_path = public, extensions
as $$
  select jsonb_build_object(
    'plan', 'free_unlimited',
    'default_app_scopes', to_jsonb(array[
      'capture:webpage',
      'schema:write',
      'graph:write',
      'memory:write',
      'memory:read_summary'
    ]::text[]),
    'default_app_categories', to_jsonb(array[
      'web:news',
      'web:research',
      'media:video',
      'ai:assistant',
      'dev:code'
    ]::text[]),
    'scopes', jsonb_build_object(
      'capture:webpage', jsonb_build_object('label', 'Capture webpages', 'description', 'Capture useful webpage content for this app.', 'grantsGraphRead', false),
      'capture:media', jsonb_build_object('label', 'Capture media context', 'description', 'Capture captions, transcripts, and media context when available.', 'grantsGraphRead', false),
      'capture:device', jsonb_build_object('label', 'Capture device activity', 'description', 'Receive allowed OS-level activity from a local helper.', 'grantsGraphRead', false, 'sensitive', true),
      'schema:write', jsonb_build_object('label', 'Create schemas', 'description', 'Form schema packets from retained activity.', 'grantsGraphRead', false),
      'graph:write', jsonb_build_object('label', 'Write graph packets', 'description', 'Store nodes, edges, and evidence packets created for this app.', 'grantsGraphRead', false),
      'memory:write', jsonb_build_object('label', 'Write memory', 'description', 'Persist retained graph evidence as memory.', 'grantsGraphRead', false),
      'memory:read_summary', jsonb_build_object('label', 'Read memory summaries', 'description', 'Receive compact memory summaries.', 'grantsGraphRead', false),
      'memory:read_evidence', jsonb_build_object('label', 'Read evidence cards', 'description', 'Receive evidence snippets and source metadata.', 'grantsGraphRead', false, 'sensitive', true),
      'memory:read_graph', jsonb_build_object('label', 'Read graph objects', 'description', 'Receive permitted nodes and edges.', 'grantsGraphRead', true, 'sensitive', true)
    ),
    'activity_categories', jsonb_build_object(
      'web:news', jsonb_build_object('label', 'News articles', 'description', 'News, politics, public affairs, and current-event pages.'),
      'web:research', jsonb_build_object('label', 'Research and learning', 'description', 'Essays, papers, documentation, tutorials, and study material.'),
      'web:commerce', jsonb_build_object('label', 'Shopping and products', 'description', 'Product pages, reviews, pricing pages, and purchase research.'),
      'web:social', jsonb_build_object('label', 'Social posts', 'description', 'Public posts, feeds, replies, creator pages, and community content.'),
      'media:video', jsonb_build_object('label', 'Video and captions', 'description', 'Videos, captions, transcripts, lectures, and long-form clips.'),
      'media:audio', jsonb_build_object('label', 'Audio and podcasts', 'description', 'Podcasts, talks, songs with available text, and spoken audio context.'),
      'ai:assistant', jsonb_build_object('label', 'AI conversations', 'description', 'Allowed conversations with AI tools such as assistants and copilots.'),
      'dev:code', jsonb_build_object('label', 'Code and developer work', 'description', 'Repositories, docs, issues, pull requests, terminals, and coding tools.'),
      'work:docs', jsonb_build_object('label', 'Documents and notes', 'description', 'Work documents, knowledge bases, notes, and writing tools.')
    ),
    'safety_rules', jsonb_build_object(
      'blockedUseCases', to_jsonb(array[
        'selling raw personal memory',
        'surveillance without user consent',
        'credit, employment, insurance, or housing decisions',
        'manipulative targeting',
        'political persuasion targeting',
        'inferring highly sensitive traits without explicit user action'
      ]::text[]),
      'requiredDeveloperPromises', to_jsonb(array[
        'ask for only the scopes needed',
        'respect selected activity categories',
        'do not sell raw memory or graph data',
        'show users where Memact is used',
        'let users disconnect access'
      ]::text[])
    ),
    'knowledge_graph_contract', jsonb_build_object(
      'memoryUnit', 'schema_packet',
      'graphObjects', to_jsonb(array['evidence','content_unit','node','edge','schema_packet']::text[]),
      'nodeTypes', to_jsonb(array['topic','claim','emotion','source','activity','tool','person','action']::text[]),
      'edgeTypes', to_jsonb(array['seen_in','repeated_with','mentions','shapes','contradicts','supports','clicked_after','searched_after']::text[]),
      'authority', 'Apps receive scoped graph access. Memact keeps raw capture, filtering, and sensitive exclusions local-first.'
    )
  );
$$;

drop function if exists public.memact_dashboard();
create or replace function public.memact_dashboard()
returns jsonb
language sql
stable
security definer
set search_path = public, extensions
as $$
  with current_actor as (
    select public.memact_require_authenticated_user() as user_id
  ),
  apps as (
    select coalesce(jsonb_agg(jsonb_build_object(
      'id', app.id,
      'owner_user_id', app.owner_user_id,
      'name', app.name,
      'slug', app.slug,
      'description', app.description,
      'developer_url', app.developer_url,
      'redirect_urls', app.redirect_urls,
      'default_scopes', to_jsonb(app.default_scopes),
      'default_categories', to_jsonb(app.default_categories),
      'created_at', app.created_at,
      'revoked_at', app.revoked_at
    ) order by app.created_at), '[]'::jsonb) as value
    from public.memact_apps app
    join current_actor on current_actor.user_id = app.owner_user_id
    where app.revoked_at is null
  ),
  api_keys as (
    select coalesce(jsonb_agg(jsonb_build_object(
      'id', key.id,
      'app_id', key.app_id,
      'owner_user_id', key.owner_user_id,
      'name', key.name,
      'key_prefix', key.key_prefix,
      'scopes', to_jsonb(key.scopes),
      'created_at', key.created_at,
      'last_used_at', key.last_used_at,
      'revoked_at', key.revoked_at
    ) order by key.created_at desc), '[]'::jsonb) as value
    from public.memact_api_keys key
    join current_actor on current_actor.user_id = key.owner_user_id
  ),
  consents as (
    select coalesce(jsonb_agg(jsonb_build_object(
      'id', consent.id,
      'user_id', consent.user_id,
      'app_id', consent.app_id,
      'scopes', to_jsonb(consent.scopes),
      'categories', to_jsonb(consent.categories),
      'created_at', consent.created_at,
      'updated_at', consent.updated_at,
      'revoked_at', consent.revoked_at
    ) order by consent.created_at desc), '[]'::jsonb) as value
    from public.memact_consents consent
    join current_actor on current_actor.user_id = consent.user_id
    where consent.revoked_at is null
  )
  select jsonb_build_object(
    'apps', apps.value,
    'api_keys', api_keys.value,
    'consents', consents.value
  )
  from apps, api_keys, consents;
$$;

drop function if exists public.memact_create_app(text, text, jsonb);
drop function if exists public.memact_create_app(text, text, jsonb, text, text[]);
create or replace function public.memact_create_app(app_name text, app_description text default '', app_redirect_urls jsonb default '[]'::jsonb, app_developer_url text default '', app_categories text[] default array['web:news','web:research','media:video','ai:assistant','dev:code']::text[])
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
    select 1 from public.memact_apps app
    where app.owner_user_id = current_user_id
      and app.revoked_at is null
      and app.slug = normalized_slug
  ) then
    raise exception 'You already have an app with this name.';
  end if;

  insert into public.memact_apps (
    owner_user_id, name, slug, description, developer_url, redirect_urls, default_categories
  )
  values (
    current_user_id,
    cleaned_name,
    normalized_slug,
    left(trim(coalesce(app_description, '')), 240),
    left(trim(coalesce(app_developer_url, '')), 300),
    case when jsonb_typeof(coalesce(app_redirect_urls, '[]'::jsonb)) = 'array' then coalesce(app_redirect_urls, '[]'::jsonb) else '[]'::jsonb end,
    clean_categories
  )
  returning * into created_app;

  perform public.memact_audit(current_user_id, 'app.create', jsonb_build_object('app_id', created_app.id, 'categories', to_jsonb(clean_categories)));

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
create or replace function public.memact_grant_consent(app_id_input uuid, scopes_input text[], categories_input text[] default array['web:news','web:research','media:video','ai:assistant','dev:code']::text[])
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
    set scopes = clean_scopes, categories = clean_categories, updated_at = timezone('utc', now())
    where id = target_consent.id
    returning * into target_consent;
    perform public.memact_audit(current_user_id, 'consent.update', jsonb_build_object('app_id', target_app.id, 'scopes', to_jsonb(clean_scopes), 'categories', to_jsonb(clean_categories)));
  else
    insert into public.memact_consents (user_id, app_id, scopes, categories)
    values (current_user_id, target_app.id, clean_scopes, clean_categories)
    returning * into target_consent;
    perform public.memact_audit(current_user_id, 'consent.grant', jsonb_build_object('app_id', target_app.id, 'scopes', to_jsonb(clean_scopes), 'categories', to_jsonb(clean_categories)));
  end if;

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

drop function if exists public.memact_create_api_key(uuid, text, text[]);
drop function if exists public.memact_create_api_key(uuid, text, text[], text[]);
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
  clean_scopes text[] := public.memact_clean_allowed_values(scopes_input, public.memact_known_scopes());
  raw_key text := 'mka_' || encode(gen_random_bytes(24), 'hex');
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
    encode(digest(raw_key::text, 'sha256'::text), 'hex'),
    left(raw_key, 12),
    clean_scopes
  )
  returning * into created_key;

  perform public.memact_audit(current_user_id, 'api_key.create', jsonb_build_object('app_id', target_app.id, 'key_id', created_key.id, 'scopes', to_jsonb(clean_scopes)));

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

drop function if exists public.memact_get_connect_app(uuid, text[], text[]);
create or replace function public.memact_get_connect_app(app_id_input uuid, scopes_input text[] default array[]::text[], categories_input text[] default array[]::text[])
returns jsonb
language plpgsql
stable
security definer
set search_path = public, extensions
as $$
declare
  current_user_id uuid := public.memact_require_authenticated_user();
  target_app public.memact_apps%rowtype;
  requested_scopes text[];
  requested_categories text[];
begin
  select * into target_app from public.memact_apps app where app.id = app_id_input and app.revoked_at is null;
  if not found then raise exception 'App not found.'; end if;
  requested_scopes := case when array_length(scopes_input, 1) is null then target_app.default_scopes else public.memact_clean_allowed_values(scopes_input, public.memact_known_scopes()) end;
  requested_categories := case when array_length(categories_input, 1) is null then target_app.default_categories else public.memact_clean_allowed_values(categories_input, public.memact_known_categories()) end;
  if array_length(requested_scopes, 1) is null then raise exception 'No valid scopes requested.'; end if;
  if array_length(requested_categories, 1) is null then raise exception 'No valid activity categories requested.'; end if;
  if not requested_categories <@ target_app.default_categories then raise exception 'This app is not registered for one or more requested categories.'; end if;

  return jsonb_build_object(
    'app', jsonb_build_object(
      'id', target_app.id,
      'name', target_app.name,
      'slug', target_app.slug,
      'description', target_app.description,
      'developer_url', target_app.developer_url,
      'redirect_urls', target_app.redirect_urls,
      'default_scopes', to_jsonb(target_app.default_scopes),
      'default_categories', to_jsonb(target_app.default_categories)
    ),
    'requested_scopes', to_jsonb(requested_scopes),
    'requested_categories', to_jsonb(requested_categories),
    'scopes', public.memact_policy()->'scopes',
    'activity_categories', public.memact_policy()->'activity_categories',
    'safety_rules', public.memact_policy()->'safety_rules',
    'policy', public.memact_policy(),
    'user_id', current_user_id
  );
end;
$$;

drop function if exists public.memact_connect_app(uuid, text[], text[]);
create or replace function public.memact_connect_app(app_id_input uuid, scopes_input text[], categories_input text[] default array[]::text[])
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
  clean_required_scopes text[] := public.memact_clean_allowed_values(required_scopes_input, public.memact_known_scopes());
  clean_required_categories text[] := public.memact_clean_allowed_values(activity_categories_input, public.memact_known_categories());
  allowed boolean;
begin
  select * into target_key
  from public.memact_api_keys key
  where key.key_hash = encode(digest(coalesce(api_key_input, '')::text, 'sha256'::text), 'hex')
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

  allowed := clean_required_scopes <@ effective_scopes and clean_required_categories <@ effective_categories;
  if allowed then update public.memact_api_keys set last_used_at = timezone('utc', now()) where id = target_key.id; end if;

  return jsonb_build_object(
    'allowed', allowed,
    'user_id', target_consent.user_id,
    'connection_id', target_consent.id,
    'app', jsonb_build_object('id', target_app.id, 'name', target_app.name, 'slug', target_app.slug, 'developer_url', target_app.developer_url),
    'key', jsonb_build_object('id', target_key.id, 'key_prefix', target_key.key_prefix, 'scopes', to_jsonb(target_key.scopes)),
    'scopes', to_jsonb(effective_scopes),
    'categories', to_jsonb(effective_categories),
    'missing_scopes', to_jsonb(array(select scope from unnest(clean_required_scopes) scope where not scope = any(effective_scopes))),
    'missing_categories', to_jsonb(array(select category from unnest(clean_required_categories) category where not category = any(effective_categories))),
    'policy', jsonb_build_object('plan', 'free_unlimited', 'graph_read_allowed', 'memory:read_graph' = any(effective_scopes)),
    'error', case when allowed then null else jsonb_build_object('code', 'scope_or_category_denied', 'message', 'API key scope or app permission does not include the requested access.') end
  );
end;
$$;

grant execute on function public.memact_policy() to anon, authenticated;
grant execute on function public.memact_dashboard() to authenticated;
grant execute on function public.memact_create_app(text, text, jsonb, text, text[]) to authenticated;
grant execute on function public.memact_grant_consent(uuid, text[], text[]) to authenticated;
grant execute on function public.memact_create_api_key(uuid, text, text[]) to authenticated;
grant execute on function public.memact_get_connect_app(uuid, text[], text[]) to authenticated;
grant execute on function public.memact_connect_app(uuid, text[], text[]) to authenticated;
grant execute on function public.memact_verify_api_key(text, text[], text[], uuid) to anon, authenticated;

notify pgrst, 'reload schema';
