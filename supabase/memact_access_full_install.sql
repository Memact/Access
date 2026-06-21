-- Memact permission-layer full Supabase install/repair SQL
-- Run this whole file in the Supabase SQL editor for a new project, or to repair/update an existing project.
-- It is the ordered combination of all migrations in supabase/migrations as of 2026-05-08.

-- === 20260507120000_memact_access.sql ===

create extension if not exists pgcrypto;

create table if not exists public.memact_apps (
  id uuid primary key default gen_random_uuid(),
  owner_user_id uuid not null references auth.users(id) on delete cascade,
  name text not null,
  slug text not null,
  description text not null default '',
  redirect_urls jsonb not null default '[]'::jsonb,
  default_scopes text[] not null default array[
    'capture:webpage',
    'schema:write',
    'graph:write',
    'memory:write',
    'memory:read_summary'
  ]::text[],
  created_at timestamptz not null default timezone('utc', now()),
  updated_at timestamptz not null default timezone('utc', now()),
  revoked_at timestamptz
);

create unique index if not exists memact_apps_owner_slug_active_idx
  on public.memact_apps(owner_user_id, slug)
  where revoked_at is null;

create table if not exists public.memact_api_keys (
  id uuid primary key default gen_random_uuid(),
  app_id uuid not null references public.memact_apps(id) on delete cascade,
  owner_user_id uuid not null references auth.users(id) on delete cascade,
  name text not null,
  key_hash text not null unique,
  key_prefix text not null,
  scopes text[] not null,
  created_at timestamptz not null default timezone('utc', now()),
  last_used_at timestamptz,
  revoked_at timestamptz,
  first_used_notified_at timestamptz
);

create table if not exists public.memact_consents (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  app_id uuid not null references public.memact_apps(id) on delete cascade,
  scopes text[] not null,
  created_at timestamptz not null default timezone('utc', now()),
  updated_at timestamptz not null default timezone('utc', now()),
  revoked_at timestamptz
);

create unique index if not exists memact_consents_user_app_active_idx
  on public.memact_consents(user_id, app_id)
  where revoked_at is null;

create table if not exists public.memact_audit_log (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users(id) on delete cascade,
  action text not null,
  details jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default timezone('utc', now())
);

alter table public.memact_apps enable row level security;
alter table public.memact_api_keys enable row level security;
alter table public.memact_consents enable row level security;
alter table public.memact_audit_log enable row level security;

drop policy if exists "memact apps own rows" on public.memact_apps;
create policy "memact apps own rows"
  on public.memact_apps
  for all
  to authenticated
  using (owner_user_id = auth.uid())
  with check (owner_user_id = auth.uid());

drop policy if exists "memact api keys own rows" on public.memact_api_keys;
create policy "memact api keys own rows"
  on public.memact_api_keys
  for all
  to authenticated
  using (owner_user_id = auth.uid())
  with check (owner_user_id = auth.uid());

drop policy if exists "memact consents own rows" on public.memact_consents;
create policy "memact consents own rows"
  on public.memact_consents
  for all
  to authenticated
  using (user_id = auth.uid())
  with check (user_id = auth.uid());

drop policy if exists "memact audit own rows" on public.memact_audit_log;
create policy "memact audit own rows"
  on public.memact_audit_log
  for select
  to authenticated
  using (user_id = auth.uid());

create or replace function public.memact_normalize_app_name(input_name text)
returns text
language sql
immutable
as $$
  select trim(both '-' from regexp_replace(lower(coalesce(input_name, '')), '[^a-z0-9]+', '-', 'g'));
$$;

create or replace function public.memact_audit(actor_user_id uuid, actor_action text, actor_details jsonb default '{}'::jsonb)
returns void
language sql
security definer
set search_path = public, extensions
as $$
  insert into public.memact_audit_log (user_id, action, details)
  values (actor_user_id, actor_action, coalesce(actor_details, '{}'::jsonb));
$$;

create or replace function public.memact_require_authenticated_user()
returns uuid
language plpgsql
stable
security definer
set search_path = public, extensions
as $$
declare
  current_user_id uuid;
begin
  current_user_id := auth.uid();
  if current_user_id is null then
    raise exception 'Please sign in again.';
  end if;
  return current_user_id;
end;
$$;

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
    'scopes', jsonb_build_object(
      'capture:webpage', jsonb_build_object(
        'label', 'Use webpage evidence',
        'description', 'Allow Memact to use approved webpage evidence to understand activity for this app.',
        'grantsGraphRead', false
      ),
      'capture:media', jsonb_build_object(
        'label', 'Use media evidence',
        'description', 'Allow Memact to use approved captions, transcripts, and media context when available.',
        'grantsGraphRead', false
      ),
      'capture:device', jsonb_build_object(
        'label', 'Use device context',
        'description', 'Allow Memact to use approved OS-level activity signals from a local helper.',
        'grantsGraphRead', false,
        'sensitive', true
      ),
      'schema:write', jsonb_build_object(
        'label', 'Create understanding schemas',
        'description', 'Allow Memact to turn retained evidence into schema packets for understanding.',
        'grantsGraphRead', false
      ),
      'graph:write', jsonb_build_object(
        'label', 'Write context graph',
        'description', 'Allow Memact to store nodes, edges, and evidence packets that describe user context for this app.',
        'grantsGraphRead', false
      ),
      'memory:write', jsonb_build_object(
        'label', 'Write memory',
        'description', 'Allow Memact to retain approved context as memory.',
        'grantsGraphRead', false
      ),
      'memory:read_summary', jsonb_build_object(
        'label', 'Read memory summaries',
        'description', 'Allow the app to receive compact summaries of approved user memory.',
        'grantsGraphRead', false
      ),
      'memory:read_evidence', jsonb_build_object(
        'label', 'Read evidence cards',
        'description', 'Allow the app to receive approved evidence snippets that explain the memory.',
        'grantsGraphRead', false,
        'sensitive', true
      ),
      'memory:read_graph', jsonb_build_object(
        'label', 'Read memory graph',
        'description', 'Allow the app to receive permitted nodes and edges about approved user memory.',
        'grantsGraphRead', true,
        'sensitive', true
      )
    ),
    'sensitive_capture_rules', jsonb_build_object(
      'blockedHostKeywords', to_jsonb(array[
        'bank','netbanking','banking','paypal','stripe','razorpay','health',
        'medical','hospital','login','password','checkout','payment','mail',
        'inbox','messages','whatsapp','telegram'
      ]::text[]),
      'blockedPathKeywords', to_jsonb(array[
        'login','signin','password','reset','checkout','payment','billing',
        'account','messages','inbox','compose','medical','health'
      ]::text[]),
      'blockedFieldTypes', to_jsonb(array[
        'password','tel','email','credit-card','cc-number','otp'
      ]::text[])
    )
  );
$$;

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
      'default_scopes', to_jsonb(app.default_scopes),
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

create or replace function public.memact_create_app(app_name text, app_description text default '', app_redirect_urls jsonb default '[]'::jsonb)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  current_user_id uuid := public.memact_require_authenticated_user();
  cleaned_name text := left(trim(coalesce(app_name, '')), 80);
  normalized_slug text := public.memact_normalize_app_name(app_name);
  created_app public.memact_apps%rowtype;
begin
  if char_length(cleaned_name) < 2 then
    raise exception 'App name must be at least 2 characters.';
  end if;

  if normalized_slug = '' then
    raise exception 'App name needs letters or numbers.';
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
    redirect_urls
  )
  values (
    current_user_id,
    cleaned_name,
    normalized_slug,
    left(trim(coalesce(app_description, '')), 240),
    case
      when jsonb_typeof(coalesce(app_redirect_urls, '[]'::jsonb)) = 'array' then coalesce(app_redirect_urls, '[]'::jsonb)
      else '[]'::jsonb
    end
  )
  returning * into created_app;

  perform public.memact_audit(current_user_id, 'app.create', jsonb_build_object('app_id', created_app.id));

  return jsonb_build_object(
    'app', jsonb_build_object(
      'id', created_app.id,
      'owner_user_id', created_app.owner_user_id,
      'name', created_app.name,
      'slug', created_app.slug,
      'description', created_app.description,
      'default_scopes', to_jsonb(created_app.default_scopes),
      'created_at', created_app.created_at,
      'revoked_at', created_app.revoked_at
    )
  );
end;
$$;

create or replace function public.memact_delete_app(app_id_input uuid)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  current_user_id uuid := public.memact_require_authenticated_user();
  deleted_at timestamptz := timezone('utc', now());
  target_app public.memact_apps%rowtype;
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

  update public.memact_apps
  set revoked_at = deleted_at, updated_at = deleted_at
  where id = target_app.id;

  update public.memact_api_keys
  set revoked_at = deleted_at
  where app_id = target_app.id
    and owner_user_id = current_user_id
    and revoked_at is null;

  update public.memact_consents
  set revoked_at = deleted_at, updated_at = deleted_at
  where app_id = target_app.id
    and user_id = current_user_id
    and revoked_at is null;

  perform public.memact_audit(current_user_id, 'app.delete', jsonb_build_object('app_id', target_app.id));

  return jsonb_build_object(
    'app', jsonb_build_object(
      'id', target_app.id,
      'owner_user_id', target_app.owner_user_id,
      'name', target_app.name,
      'slug', target_app.slug,
      'description', target_app.description,
      'default_scopes', to_jsonb(target_app.default_scopes),
      'created_at', target_app.created_at,
      'revoked_at', deleted_at
    )
  );
end;
$$;

create or replace function public.memact_grant_consent(app_id_input uuid, scopes_input text[])
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  current_user_id uuid := public.memact_require_authenticated_user();
  clean_scopes text[] := coalesce(scopes_input, array[]::text[]);
  target_app public.memact_apps%rowtype;
  target_consent public.memact_consents%rowtype;
begin
  select *
  into target_app
  from public.memact_apps app
  where app.id = app_id_input
    and app.revoked_at is null;

  if not found then
    raise exception 'App not found.';
  end if;

  select *
  into target_consent
  from public.memact_consents consent
  where consent.user_id = current_user_id
    and consent.app_id = target_app.id
    and consent.revoked_at is null;

  if found then
    update public.memact_consents
    set scopes = clean_scopes, updated_at = timezone('utc', now())
    where id = target_consent.id
    returning * into target_consent;
    perform public.memact_audit(current_user_id, 'consent.update', jsonb_build_object('app_id', target_app.id, 'scopes', to_jsonb(clean_scopes)));
  else
    insert into public.memact_consents (user_id, app_id, scopes)
    values (current_user_id, target_app.id, clean_scopes)
    returning * into target_consent;
    perform public.memact_audit(current_user_id, 'consent.grant', jsonb_build_object('app_id', target_app.id, 'scopes', to_jsonb(clean_scopes)));
  end if;

  return jsonb_build_object(
    'consent', jsonb_build_object(
      'id', target_consent.id,
      'user_id', target_consent.user_id,
      'app_id', target_consent.app_id,
      'scopes', to_jsonb(target_consent.scopes),
      'created_at', target_consent.created_at,
      'updated_at', target_consent.updated_at,
      'revoked_at', target_consent.revoked_at
    )
  );
end;
$$;

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
    encode(extensions.digest(raw_key, 'sha256'), 'hex'),
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

create or replace function public.memact_revoke_api_key(key_id_input uuid)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  current_user_id uuid := public.memact_require_authenticated_user();
  revoked_key public.memact_api_keys%rowtype;
begin
  update public.memact_api_keys
  set revoked_at = coalesce(revoked_at, timezone('utc', now()))
  where id = key_id_input
    and owner_user_id = current_user_id
  returning * into revoked_key;

  if not found then
    raise exception 'API key not found.';
  end if;

  perform public.memact_audit(current_user_id, 'api_key.revoke', jsonb_build_object('key_id', revoked_key.id));

  return jsonb_build_object(
    'api_key', jsonb_build_object(
      'id', revoked_key.id,
      'app_id', revoked_key.app_id,
      'owner_user_id', revoked_key.owner_user_id,
      'name', revoked_key.name,
      'key_prefix', revoked_key.key_prefix,
      'scopes', to_jsonb(revoked_key.scopes),
      'created_at', revoked_key.created_at,
      'last_used_at', revoked_key.last_used_at,
      'revoked_at', revoked_key.revoked_at
    )
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
  where key.key_hash = encode(extensions.digest(coalesce(api_key_input, ''), 'sha256'), 'hex')
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
        'code', 'consent_required',
        'message', 'User permission is required for this app.'
      )
    );
  end if;

  select coalesce(array_agg(scope), array[]::text[])
  into effective_scopes
  from unnest(target_key.scopes) as scope
  where scope = any(target_consent.scopes);

  allowed := coalesce(required_scopes_input, array[]::text[]) <@ effective_scopes;

  update public.memact_api_keys
  set last_used_at = timezone('utc', now())
  where id = target_key.id;

  perform public.memact_audit(
    target_key.owner_user_id,
    case when allowed then 'access.allow' else 'access.deny' end,
    jsonb_build_object(
      'app_id', target_app.id,
      'required_scopes', to_jsonb(coalesce(required_scopes_input, array[]::text[])),
      'effective_scopes', to_jsonb(effective_scopes)
    )
  );

  if not allowed then
    return jsonb_build_object(
      'allowed', false,
      'error', jsonb_build_object(
        'code', 'scope_denied',
        'message', 'API key or saved permissions do not include the required scopes.'
      ),
      'scopes', to_jsonb(effective_scopes)
    );
  end if;

  return jsonb_build_object(
    'allowed', true,
    'user_id', target_key.owner_user_id,
    'app', jsonb_build_object(
      'id', target_app.id,
      'owner_user_id', target_app.owner_user_id,
      'name', target_app.name,
      'slug', target_app.slug,
      'description', target_app.description,
      'default_scopes', to_jsonb(target_app.default_scopes),
      'created_at', target_app.created_at,
      'revoked_at', target_app.revoked_at
    ),
    'scopes', to_jsonb(effective_scopes),
    'policy', jsonb_build_object(
      'plan', 'free_unlimited',
      'graph_read_allowed', 'memory:read_graph' = any(effective_scopes)
    )
  );
end;
$$;

grant execute on function public.memact_policy() to anon, authenticated;
grant execute on function public.memact_dashboard() to authenticated;
grant execute on function public.memact_create_app(text, text, jsonb) to authenticated;
grant execute on function public.memact_delete_app(uuid) to authenticated;
grant execute on function public.memact_grant_consent(uuid, text[]) to authenticated;
grant execute on function public.memact_create_api_key(uuid, text, text[]) to authenticated;
grant execute on function public.memact_revoke_api_key(uuid) to authenticated;
grant execute on function public.memact_verify_api_key(text, text[]) to anon, authenticated;

-- === 20260507171000_fix_api_key_entropy.sql ===

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
    encode(extensions.digest(raw_key, 'sha256'), 'hex'),
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

-- === 20260507190000_qualify_access_crypto.sql ===

create schema if not exists extensions;
do $$
begin
  if exists (select 1 from pg_extension where extname = 'pgcrypto') then
    alter extension pgcrypto set schema extensions;
  else
    create extension pgcrypto with schema extensions;
  end if;
end $$;

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
    encode(extensions.digest(raw_key, 'sha256'), 'hex'),
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
  where key.key_hash = encode(extensions.digest(coalesce(api_key_input, ''), 'sha256'), 'hex')
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

-- === 20260507203000_connect_categories_guardrails.sql ===

create schema if not exists extensions;
do $$
begin
  if exists (select 1 from pg_extension where extname = 'pgcrypto') then
    alter extension pgcrypto set schema extensions;
  else
    create extension pgcrypto with schema extensions;
  end if;
end $$;

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
    'memory:read_graph',
    'capture:event_write',
    'feature:list',
    'feature:run',
    'context:read',
    'context:write',
    'schema:read'
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
      'capture:webpage', jsonb_build_object('label', 'Use webpage evidence', 'description', 'Use approved webpage evidence to understand activity for this app.', 'grantsGraphRead', false),
      'capture:media', jsonb_build_object('label', 'Use media evidence', 'description', 'Use approved captions, transcripts, and media context when available.', 'grantsGraphRead', false),
      'capture:device', jsonb_build_object('label', 'Use device context', 'description', 'Use approved OS-level activity signals from a local helper.', 'grantsGraphRead', false, 'sensitive', true),
      'schema:write', jsonb_build_object('label', 'Create understanding schemas', 'description', 'Turn retained evidence into schema packets for understanding.', 'grantsGraphRead', false),
      'graph:write', jsonb_build_object('label', 'Write context graph', 'description', 'Store nodes, edges, and evidence packets that describe user context for this app.', 'grantsGraphRead', false),
      'memory:write', jsonb_build_object('label', 'Write memory', 'description', 'Retain approved context as memory.', 'grantsGraphRead', false),
      'memory:read_summary', jsonb_build_object('label', 'Read memory summaries', 'description', 'Receive compact summaries of approved user memory.', 'grantsGraphRead', false),
      'memory:read_evidence', jsonb_build_object('label', 'Read evidence cards', 'description', 'Receive approved evidence snippets that explain the memory.', 'grantsGraphRead', false, 'sensitive', true),
      'memory:read_graph', jsonb_build_object('label', 'Read memory graph', 'description', 'Receive permitted nodes and edges about approved user memory.', 'grantsGraphRead', true, 'sensitive', true),
      'capture:event_write', jsonb_build_object('label', 'Send app activity', 'description', 'Send approved app activity for user review.', 'grantsGraphRead', false),
      'feature:list', jsonb_build_object('label', 'List older features', 'description', 'Compatibility scope for older feature integrations.', 'grantsGraphRead', false),
      'feature:run', jsonb_build_object('label', 'Run older features', 'description', 'Compatibility scope for older feature integrations.', 'grantsGraphRead', false),
      'context:read', jsonb_build_object('label', 'Read allowed memory', 'description', 'Receive memory the user approved for this category.', 'grantsGraphRead', false),
      'context:write', jsonb_build_object('label', 'Suggest memory', 'description', 'Suggest memory the user can accept, edit, reject, or delete.', 'grantsGraphRead', false),
      'schema:read', jsonb_build_object('label', 'Read schema packets', 'description', 'Use permitted schema packet summaries for features.', 'grantsGraphRead', false)
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
        'selling raw personal context',
        'surveillance without user consent',
        'credit, employment, insurance, or housing decisions',
        'manipulative targeting',
        'political persuasion targeting',
        'inferring highly sensitive traits without explicit user action'
      ]::text[]),
      'requiredDeveloperPromises', to_jsonb(array[
        'ask for only the scopes needed',
        'respect selected activity categories',
        'do not sell raw memory, context, or graph data',
        'show users where Memact is used',
        'let users disconnect access'
      ]::text[])
    ),
    'knowledge_graph_contract', jsonb_build_object(
      'memoryUnit', 'schema_packet',
      'graphObjects', to_jsonb(array['evidence','content_unit','node','edge','schema_packet']::text[]),
      'nodeTypes', to_jsonb(array['topic','claim','emotion','source','activity','tool','person','action']::text[]),
      'edgeTypes', to_jsonb(array['seen_in','repeated_with','mentions','shapes','contradicts','supports','clicked_after','searched_after']::text[]),
      'authority', 'Apps receive scoped understanding from approved memory. Memact keeps raw capture, filtering, and sensitive exclusions local-first.'
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
drop function if exists public.memact_create_app(text, text, text[]);
drop function if exists public.memact_create_app(text, text, text[], text);
drop function if exists public.memact_create_app(text, text, text[], text, text[]);
drop function if exists public.memact_create_app(text[], text, text, text, text[]);
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

create or replace function public.memact_understanding_strategy(scopes_input text[] default array[]::text[], categories_input text[] default array[]::text[])
returns jsonb
language sql
stable
security definer
set search_path = public, extensions
as $$
  with clean as (
    select
      public.memact_clean_allowed_values(scopes_input, public.memact_known_scopes()) as scopes,
      public.memact_clean_allowed_values(categories_input, public.memact_known_categories()) as categories
  ),
  category_rows as (
    select category,
      case category
        when 'web:news' then jsonb_build_object(
          'category', category,
          'label', 'News article understanding',
          'capture', to_jsonb(array['article url','publisher/domain','headline','author when public','published/updated time','section headings','selected article text','visible citations and links']::text[]),
          'understand', to_jsonb(array['main claim','supporting evidence','named people and organizations','topic trail','stance or framing','reading intent']::text[]),
          'schema', to_jsonb(array['article','claim','source','topic','user_attention']::text[]),
          'memory', to_jsonb(array['topics followed repeatedly','sources revisited','claims compared across articles','attention shifts between related stories']::text[])
        )
        when 'web:social' then jsonb_build_object(
          'category', category,
          'label', 'Social post understanding',
          'capture', to_jsonb(array['public post url','creator handle','caption or post text','thread context','public engagement labels','linked media metadata']::text[]),
          'understand', to_jsonb(array['topics followed','creator affinity','community context','sentiment of interest','reply or share intent']::text[]),
          'schema', to_jsonb(array['post','creator','topic','community','interest_signal']::text[]),
          'memory', to_jsonb(array['creators revisited','communities followed','topics that sustain attention','public interaction patterns']::text[])
        )
        when 'media:video' then jsonb_build_object(
          'category', category,
          'label', 'Video understanding',
          'capture', to_jsonb(array['video url','title','channel','captions/transcript','chapter markers','watch position','visible description']::text[]),
          'understand', to_jsonb(array['watched concepts','important moments','speaker claims','learning or entertainment intent','rewatch cues']::text[]),
          'schema', to_jsonb(array['video','speaker','claim','moment','topic']::text[]),
          'memory', to_jsonb(array['channels revisited','topics watched deeply','unfinished videos','claims compared with other sources']::text[])
        )
        when 'dev:code' then jsonb_build_object(
          'category', category,
          'label', 'Developer workflow understanding',
          'capture', to_jsonb(array['repository name','file path metadata','issue or PR titles','terminal command labels','docs pages','error messages']::text[]),
          'understand', to_jsonb(array['implementation goal','bug context','dependencies touched','review risk','next debugging step']::text[]),
          'schema', to_jsonb(array['repo','file','issue','error','implementation_step']::text[]),
          'memory', to_jsonb(array['project conventions','repeated errors','files frequently touched together','review preferences']::text[])
        )
        else jsonb_build_object(
          'category', category,
          'label', coalesce(public.memact_policy()->'activity_categories'->category->>'label', category),
          'capture', to_jsonb(array['approved page or activity metadata','selected text','visible context','source url']::text[]),
          'understand', to_jsonb(array['user goal','topic','context','next action']::text[]),
          'schema', to_jsonb(array['activity','topic','source','action']::text[]),
          'memory', to_jsonb(array['repeated topics','stable preferences','unfinished actions']::text[])
        )
      end as algorithm
    from clean, unnest(clean.categories) category
  )
  select jsonb_build_object(
    'id', 'understanding_' || substr(encode(extensions.digest(array_to_string((select scopes from clean), '+') || '__' || array_to_string((select categories from clean), '+'), 'sha256'), 'hex'), 1, 12),
    'product', 'memact',
    'tagline', 'Your Identity. Your Choice.',
    'subtagline', 'See what apps know about you and control it.',
    'summary', 'Use permitted categories to suggest memory and return only allowed memory to apps.',
    'scopes', to_jsonb((select scopes from clean)),
    'categories', to_jsonb((select categories from clean)),
    'category_algorithms', coalesce((select jsonb_agg(algorithm) from category_rows), '[]'::jsonb),
    'capture_plan', jsonb_build_object(
      'local_only_raw_capture', true,
      'allowed_inputs', coalesce((select jsonb_agg(distinct value) from category_rows, jsonb_array_elements_text(algorithm->'capture') value), '[]'::jsonb)
    ),
    'understanding_plan', jsonb_build_object(
      'outputs', coalesce((select jsonb_agg(distinct value) from category_rows, jsonb_array_elements_text(algorithm->'understand') value), '[]'::jsonb),
      'schema_packets', case when (select 'schema:write' = any(scopes) from clean) then coalesce((select jsonb_agg(distinct value) from category_rows, jsonb_array_elements_text(algorithm->'schema') value), '[]'::jsonb) else '[]'::jsonb end,
      'graph_write', (select 'graph:write' = any(scopes) from clean),
      'memory_write', (select 'memory:write' = any(scopes) from clean)
    ),
    'delivery_plan', jsonb_build_object(
      'summaries', (select 'memory:read_summary' = any(scopes) from clean),
      'evidence_cards', (select 'memory:read_evidence' = any(scopes) from clean),
      'graph_objects', (select 'memory:read_graph' = any(scopes) from clean),
      'feature_runs', (select 'feature:run' = any(scopes) from clean)
    ),
    'storage_plan', jsonb_build_object(
      'default', jsonb_build_object('id', 'local-first-memory', 'label', 'Local-first memory', 'description', 'Sensitive evidence stays local by default. Apps receive only memory allowed by consent.'),
      'future_user_cloud', jsonb_build_object('id', 'user-owned-cloud-memory', 'label', 'User-owned cloud memory', 'status', 'planned', 'description', 'Users can later choose personal cloud storage through remote memory adapters without changing the API contract.')
    )
  )
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
    'understanding_strategy', public.memact_understanding_strategy(effective_scopes, effective_categories),
    'missing_scopes', to_jsonb(array(select scope from unnest(clean_required_scopes) scope where not scope = any(effective_scopes))),
    'missing_categories', to_jsonb(array(select category from unnest(clean_required_categories) category where not category = any(effective_categories))),
    'policy', jsonb_build_object('plan', 'free_unlimited', 'graph_read_allowed', 'memory:read_graph' = any(effective_scopes)),
    'error', case when allowed then null else jsonb_build_object('code', 'scope_or_category_denied', 'message', 'API key scope or app permission does not include the requested access.') end
  );
end;
$$;

grant execute on function public.memact_understanding_strategy(text[], text[]) to anon, authenticated;
grant execute on function public.memact_verify_api_key(text, text[], text[], uuid) to anon, authenticated;

notify pgrst, 'reload schema';

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
  )
  select jsonb_build_object(
    'id', 'policy_' || substr(encode(extensions.digest(coalesce(app_id_input::text, '') || '__' || array_to_string((select scopes from clean), '+') || '__' || array_to_string((select categories from clean), '+') || '__' || (select purpose from clean), 'sha256'), 'hex'), 1, 12),
    'app_id', app_id_input,
    'product', 'memact',
    'tagline', 'Your Identity. Your Choice.',
    'subtagline', 'See what apps know about you and control it.',
    'purpose', (select purpose from clean),
    'scopes', to_jsonb((select scopes from clean)),
    'categories', to_jsonb((select categories from clean)),
    'strategy', public.memact_understanding_strategy((select scopes from clean), (select categories from clean)),
    'warnings', case when (select 'memory:read_graph' = any(scopes) or 'capture:device' = any(scopes) from clean) then to_jsonb(array['This policy includes sensitive permissions. Explain why users need them.']::text[]) else '[]'::jsonb end,
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

-- === 20260522110000_feature_connections.sql ===

create table if not exists public.memact_feature_connections (
  id uuid primary key default gen_random_uuid(),
  owner_user_id uuid not null references auth.users(id) on delete cascade,
  app_id uuid not null references public.memact_apps(id) on delete cascade,
  api_key_id uuid not null references public.memact_api_keys(id) on delete cascade,
  feature_id text not null,
  created_at timestamptz not null default timezone('utc', now()),
  disconnected_at timestamptz
);

create index if not exists memact_feature_connections_owner_idx
  on public.memact_feature_connections(owner_user_id);

create index if not exists memact_feature_connections_app_idx
  on public.memact_feature_connections(app_id);

create unique index if not exists memact_feature_connections_active_idx
  on public.memact_feature_connections(owner_user_id, app_id, api_key_id, feature_id)
  where disconnected_at is null;

alter table public.memact_feature_connections enable row level security;

drop policy if exists "memact feature connections own rows" on public.memact_feature_connections;
create policy "memact feature connections own rows"
  on public.memact_feature_connections
  for all
  to authenticated
  using (owner_user_id = auth.uid())
  with check (owner_user_id = auth.uid());

notify pgrst, 'reload schema';

create table if not exists public.memact_schema_definitions (
  id uuid primary key default extensions.gen_random_uuid(),
  app_id uuid not null,
  schema_id text not null,
  category text not null default 'general',
  description text not null default '',
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default timezone('utc', now()),
  updated_at timestamptz not null default timezone('utc', now()),
  unique (app_id, schema_id)
);

create table if not exists public.memact_subschema_definitions (
  id uuid primary key default extensions.gen_random_uuid(),
  app_id uuid not null,
  schema_id text not null,
  sub_schema_id text not null,
  description text not null default '',
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default timezone('utc', now()),
  updated_at timestamptz not null default timezone('utc', now()),
  unique (app_id, schema_id, sub_schema_id)
);

create index if not exists memact_schema_definitions_app_id_idx
  on public.memact_schema_definitions (app_id);

create index if not exists memact_schema_definitions_schema_id_idx
  on public.memact_schema_definitions (schema_id);

create index if not exists memact_subschema_definitions_app_schema_idx
  on public.memact_subschema_definitions (app_id, schema_id);

create or replace function public.memact_schema_definition_payload(schema_row public.memact_schema_definitions)
returns jsonb
language sql
stable
as $$
  select jsonb_build_object(
    'schema_id', schema_row.schema_id,
    'app_id', schema_row.app_id,
    'category', schema_row.category,
    'description', schema_row.description,
    'metadata', schema_row.metadata,
    'created_at', schema_row.created_at,
    'updated_at', schema_row.updated_at,
    'subschemas', coalesce((
      select jsonb_agg(jsonb_build_object(
        'schema_id', subschema.schema_id,
        'sub_schema_id', subschema.sub_schema_id,
        'app_id', subschema.app_id,
        'description', subschema.description,
        'metadata', subschema.metadata,
        'created_at', subschema.created_at,
        'updated_at', subschema.updated_at
      ) order by subschema.sub_schema_id)
      from public.memact_subschema_definitions subschema
      where subschema.app_id = schema_row.app_id
        and subschema.schema_id = schema_row.schema_id
    ), '[]'::jsonb)
  );
$$;

create or replace function public.memact_upsert_schema_definition(
  api_key_input text,
  consent_id_input uuid,
  schema_id_input text,
  category_input text default 'general',
  description_input text default '',
  metadata_input jsonb default '{}'::jsonb
)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  verification jsonb;
  app_id_value uuid;
  clean_schema_id text := lower(regexp_replace(coalesce(schema_id_input, ''), '[^a-zA-Z0-9:_-]+', '-', 'g'));
  clean_category text := lower(regexp_replace(coalesce(category_input, 'general'), '[^a-zA-Z0-9:_-]+', '-', 'g'));
  saved_schema public.memact_schema_definitions%rowtype;
begin
  if clean_schema_id = '' then
    return jsonb_build_object('allowed', false, 'error', jsonb_build_object('code', 'missing_schema_id', 'message', 'Schema id is required.'));
  end if;

  verification := public.memact_verify_api_key(
    api_key_input,
    array['schema:write']::text[],
    case when clean_category = '' or clean_category = 'general' then array[]::text[] else array[clean_category]::text[] end,
    consent_id_input
  );
  if not coalesce((verification->>'allowed')::boolean, false) then return verification; end if;

  app_id_value := nullif(verification #>> '{app,id}', '')::uuid;
  if app_id_value is null then
    return jsonb_build_object('allowed', false, 'error', jsonb_build_object('code', 'app_missing', 'message', 'App could not be resolved.'));
  end if;

  insert into public.memact_schema_definitions (app_id, schema_id, category, description, metadata, updated_at)
  values (app_id_value, clean_schema_id, case when clean_category = '' then 'general' else clean_category end, left(coalesce(description_input, ''), 500), coalesce(metadata_input, '{}'::jsonb), timezone('utc', now()))
  on conflict (app_id, schema_id)
  do update set category = excluded.category, description = excluded.description, metadata = excluded.metadata, updated_at = timezone('utc', now())
  returning * into saved_schema;

  insert into public.memact_usage_events (app_id, action, details)
  values (app_id_value, 'schema.definition.upsert', jsonb_build_object('schema_id', clean_schema_id));

  return jsonb_build_object('allowed', true, 'schema', public.memact_schema_definition_payload(saved_schema));
end;
$$;

create or replace function public.memact_upsert_subschema_definition(
  api_key_input text,
  consent_id_input uuid,
  schema_id_input text,
  sub_schema_id_input text,
  description_input text default '',
  metadata_input jsonb default '{}'::jsonb
)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  verification jsonb;
  app_id_value uuid;
  clean_schema_id text := lower(regexp_replace(coalesce(schema_id_input, ''), '[^a-zA-Z0-9:_-]+', '-', 'g'));
  clean_sub_schema_id text := lower(regexp_replace(coalesce(sub_schema_id_input, ''), '[^a-zA-Z0-9:_-]+', '-', 'g'));
  saved_subschema public.memact_subschema_definitions%rowtype;
begin
  if clean_schema_id = '' then
    return jsonb_build_object('allowed', false, 'error', jsonb_build_object('code', 'missing_schema_id', 'message', 'Schema id is required.'));
  end if;
  if clean_sub_schema_id = '' then
    return jsonb_build_object('allowed', false, 'error', jsonb_build_object('code', 'missing_subschema_id', 'message', 'Subschema id is required.'));
  end if;

  verification := public.memact_verify_api_key(api_key_input, array['schema:write']::text[], array[]::text[], consent_id_input);
  if not coalesce((verification->>'allowed')::boolean, false) then return verification; end if;

  app_id_value := nullif(verification #>> '{app,id}', '')::uuid;
  if app_id_value is null then
    return jsonb_build_object('allowed', false, 'error', jsonb_build_object('code', 'app_missing', 'message', 'App could not be resolved.'));
  end if;

  if not exists (select 1 from public.memact_schema_definitions where app_id = app_id_value and schema_id = clean_schema_id) then
    return jsonb_build_object('allowed', false, 'error', jsonb_build_object('code', 'schema_not_found', 'message', 'Schema definition not found.'));
  end if;

  insert into public.memact_subschema_definitions (app_id, schema_id, sub_schema_id, description, metadata, updated_at)
  values (app_id_value, clean_schema_id, clean_sub_schema_id, left(coalesce(description_input, ''), 500), coalesce(metadata_input, '{}'::jsonb), timezone('utc', now()))
  on conflict (app_id, schema_id, sub_schema_id)
  do update set description = excluded.description, metadata = excluded.metadata, updated_at = timezone('utc', now())
  returning * into saved_subschema;

  insert into public.memact_usage_events (app_id, action, details)
  values (app_id_value, 'schema.subschema.upsert', jsonb_build_object('schema_id', clean_schema_id, 'sub_schema_id', clean_sub_schema_id));

  return jsonb_build_object('allowed', true, 'subschema', to_jsonb(saved_subschema));
end;
$$;

create or replace function public.memact_list_schema_definitions(
  api_key_input text,
  consent_id_input uuid default null,
  activity_categories_input text[] default array[]::text[]
)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  verification jsonb;
  app_id_value uuid;
  schemas_payload jsonb;
begin
  verification := public.memact_verify_api_key(api_key_input, array['schema:read']::text[], activity_categories_input, consent_id_input);
  if not coalesce((verification->>'allowed')::boolean, false) then return verification; end if;

  app_id_value := nullif(verification #>> '{app,id}', '')::uuid;
  select coalesce(jsonb_agg(public.memact_schema_definition_payload(schema_row) order by schema_row.schema_id), '[]'::jsonb)
    into schemas_payload
  from public.memact_schema_definitions schema_row
  where schema_row.app_id = app_id_value;

  return jsonb_build_object('allowed', true, 'schema_definitions', schemas_payload, 'schemas', '[]'::jsonb);
end;
$$;

create or replace function public.memact_get_schema_definition(
  api_key_input text,
  consent_id_input uuid,
  schema_id_input text,
  activity_categories_input text[] default array[]::text[]
)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  verification jsonb;
  app_id_value uuid;
  clean_schema_id text := lower(regexp_replace(coalesce(schema_id_input, ''), '[^a-zA-Z0-9:_-]+', '-', 'g'));
  schema_row public.memact_schema_definitions%rowtype;
begin
  if clean_schema_id = '' then
    return jsonb_build_object('allowed', false, 'error', jsonb_build_object('code', 'missing_schema_id', 'message', 'Schema id is required.'));
  end if;

  verification := public.memact_verify_api_key(api_key_input, array['schema:read']::text[], activity_categories_input, consent_id_input);
  if not coalesce((verification->>'allowed')::boolean, false) then return verification; end if;

  app_id_value := nullif(verification #>> '{app,id}', '')::uuid;
  select * into schema_row from public.memact_schema_definitions where app_id = app_id_value and schema_id = clean_schema_id limit 1;
  if not found then
    return jsonb_build_object('allowed', false, 'error', jsonb_build_object('code', 'schema_not_found', 'message', 'Schema definition not found.'));
  end if;

  return jsonb_build_object('allowed', true, 'schema', public.memact_schema_definition_payload(schema_row));
end;
$$;

grant execute on function public.memact_schema_definition_payload to anon, authenticated;
grant execute on function public.memact_upsert_schema_definition(text, uuid, text, text, text, jsonb) to anon, authenticated;
grant execute on function public.memact_upsert_subschema_definition(text, uuid, text, text, text, jsonb) to anon, authenticated;
grant execute on function public.memact_list_schema_definitions(text, uuid, text[]) to anon, authenticated;
grant execute on function public.memact_get_schema_definition(text, uuid, text, text[]) to anon, authenticated;

notify pgrst, 'reload schema';


-- === 20260617000000_memact_notebook.sql ===

-- Create memact profiles table
create table if not exists public.memact_profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  username text not null unique,
  full_name text not null,
  created_at timestamptz not null default timezone('utc', now()),
  constraint username_length check (char_length(username) >= 3),
  constraint username_format check (username ~ '^[a-z0-9._-]+$')
);

-- Create memact contributions table
create table if not exists public.memact_contributions (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  content text not null,
  contributor_type text not null check (contributor_type in ('user', 'friend', 'app', 'agent', 'organization')),
  contributor_name text not null,
  status text not null check (status in ('pending', 'approved', 'rejected')),
  visibility text not null check (visibility in ('private', 'friends', 'apps', 'agents', 'public')),
  is_starred boolean not null default false,
  created_at timestamptz not null default timezone('utc', now())
);

-- Create memact connections table
create table if not exists public.memact_connections (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  name text not null,
  type text not null check (type in ('app', 'agent', 'friend')),
  active boolean not null default true,
  created_at timestamptz not null default timezone('utc', now())
);

-- Enable Row Level Security (RLS)
alter table public.memact_profiles enable row level security;
alter table public.memact_contributions enable row level security;
alter table public.memact_connections enable row level security;

-- Policies for profiles
drop policy if exists "allow public read on profiles" on public.memact_profiles;
create policy "allow public read on profiles"
  on public.memact_profiles
  for select
  to anon, authenticated
  using (true);

drop policy if exists "allow users to manage own profile" on public.memact_profiles;
create policy "allow users to manage own profile"
  on public.memact_profiles
  for all
  to authenticated
  using (id = auth.uid())
  with check (id = auth.uid());

-- Policies for contributions
drop policy if exists "allow users to manage own contributions" on public.memact_contributions;
create policy "allow users to manage own contributions"
  on public.memact_contributions
  for all
  to authenticated
  using (user_id = auth.uid())
  with check (user_id = auth.uid());

drop policy if exists "allow public read on approved public contributions" on public.memact_contributions;
create policy "allow public read on approved public contributions"
  on public.memact_contributions
  for select
  to anon, authenticated
  using (visibility = 'public' and status = 'approved');

-- Policies for connections
drop policy if exists "allow users to manage own connections" on public.memact_connections;
create policy "allow users to manage own connections"
  on public.memact_connections
  for all
  to authenticated
  using (user_id = auth.uid())
  with check (user_id = auth.uid());


-- === 20260619120000_cleanup_legacy.sql ===

-- Drop legacy functions
drop function if exists public.memact_schema_definition_payload cascade;
drop function if exists public.memact_upsert_schema_definition cascade;
drop function if exists public.memact_upsert_subschema_definition cascade;
drop function if exists public.memact_list_schema_definitions cascade;
drop function if exists public.memact_get_schema_definition cascade;

-- Drop legacy tables and their cascades (indexes, policies, etc.)
drop table if exists public.memact_subschema_definitions cascade;
drop table if exists public.memact_schema_definitions cascade;
drop table if exists public.memact_feature_connections cascade;
drop table if exists public.memact_capture_events cascade;
drop table if exists public.memact_feature_registry cascade;
drop table if exists public.memact_feature_runs cascade;
drop table if exists public.memact_schema_packets cascade;
drop table if exists public.memact_memory_records cascade;
drop table if exists public.memact_usage_events cascade;

notify pgrst, 'reload schema';


-- === 20260619130000_notebook_rpcs.sql ===

-- Create RPC function to propose contribution
create or replace function public.memact_propose_contribution(
  api_key_input text,
  content_input text,
  contributor_type_input text,
  contributor_name_input text,
  visibility_input text
)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  verification jsonb;
  new_contribution_id uuid;
begin
  verification := public.memact_verify_api_key(api_key_input, array['context:write']::text[], array[]::text[]);
  if not (verification->>'allowed')::boolean then
    raise exception 'Access denied: %', verification->'error'->>'message';
  end if;

  insert into public.memact_contributions (
    user_id,
    content,
    contributor_type,
    contributor_name,
    status,
    visibility,
    is_starred
  ) values (
    (verification->>'user_id')::uuid,
    content_input,
    contributor_type_input,
    contributor_name_input,
    'pending',
    visibility_input,
    false
  ) returning id into new_contribution_id;

  return jsonb_build_object(
    'accepted', true,
    'contribution', jsonb_build_object(
      'id', new_contribution_id,
      'user_id', verification->>'user_id',
      'content', content_input,
      'contributor_type', contributor_type_input,
      'contributor_name', contributor_name_input,
      'status', 'pending',
      'visibility', visibility_input,
      'is_starred', false
    )
  );
end;
$$;

grant execute on function public.memact_propose_contribution(text, text, text, text, text) to anon, authenticated;

-- Create RPC function to get contributions for app (CAP)
create or replace function public.memact_get_contributions_for_app(
  api_key_input text,
  required_scopes_input text[],
  activity_categories_input text[]
)
returns table (
  id uuid,
  user_id uuid,
  content text,
  contributor_type text,
  contributor_name text,
  status text,
  visibility text,
  is_starred boolean,
  created_at timestamptz
)
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  verification jsonb;
begin
  verification := public.memact_verify_api_key(api_key_input, required_scopes_input, activity_categories_input);
  if not (verification->>'allowed')::boolean then
    raise exception 'Access denied: %', verification->'error'->>'message';
  end if;

  return query
  select c.id, c.user_id, c.content, c.contributor_type, c.contributor_name, c.status, c.visibility, c.is_starred, c.created_at
  from public.memact_contributions c
  where c.user_id = (verification->>'user_id')::uuid
    and c.status = 'approved'
    and c.visibility in ('public', 'apps', 'agents');
end;
$$;

grant execute on function public.memact_get_contributions_for_app(text, text[], text[]) to anon, authenticated;

notify pgrst, 'reload schema';
