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
        'label', 'Capture webpages',
        'description', 'Allow Memact to capture useful webpage content for this app.',
        'grantsGraphRead', false
      ),
      'capture:media', jsonb_build_object(
        'label', 'Capture media context',
        'description', 'Allow Memact to capture captions, transcripts, and media context when available.',
        'grantsGraphRead', false
      ),
      'capture:device', jsonb_build_object(
        'label', 'Capture device activity',
        'description', 'Allow Memact to receive allowed OS-level activity from a local helper.',
        'grantsGraphRead', false,
        'sensitive', true
      ),
      'schema:write', jsonb_build_object(
        'label', 'Create schemas',
        'description', 'Allow Memact to form schema packets from retained activity.',
        'grantsGraphRead', false
      ),
      'graph:write', jsonb_build_object(
        'label', 'Write graph packets',
        'description', 'Allow Memact to store nodes, edges, and evidence packets created for this app.',
        'grantsGraphRead', false
      ),
      'memory:write', jsonb_build_object(
        'label', 'Write memory',
        'description', 'Allow Memact to persist retained graph evidence as memory.',
        'grantsGraphRead', false
      ),
      'memory:read_summary', jsonb_build_object(
        'label', 'Read memory summaries',
        'description', 'Allow the app to receive compact memory summaries.',
        'grantsGraphRead', false
      ),
      'memory:read_evidence', jsonb_build_object(
        'label', 'Read evidence cards',
        'description', 'Allow the app to receive evidence snippets and source metadata.',
        'grantsGraphRead', false,
        'sensitive', true
      ),
      'memory:read_graph', jsonb_build_object(
        'label', 'Read graph objects',
        'description', 'Allow the app to receive permitted nodes and edges.',
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
