do $$
begin
  if exists (select 1 from pg_extension where extname = 'pgcrypto') then
    alter extension pgcrypto set schema extensions;
  else
    create extension pgcrypto with schema extensions;
  end if;
end
$$;

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

  if not coalesce((verification->>'allowed')::boolean, false) then
    return verification;
  end if;

  app_id_value := nullif(verification #>> '{app,id}', '')::uuid;
  if app_id_value is null then
    return jsonb_build_object('allowed', false, 'error', jsonb_build_object('code', 'app_missing', 'message', 'App could not be resolved.'));
  end if;

  insert into public.memact_schema_definitions (
    app_id,
    schema_id,
    category,
    description,
    metadata,
    updated_at
  )
  values (
    app_id_value,
    clean_schema_id,
    case when clean_category = '' then 'general' else clean_category end,
    left(coalesce(description_input, ''), 500),
    coalesce(metadata_input, '{}'::jsonb),
    timezone('utc', now())
  )
  on conflict (app_id, schema_id)
  do update set
    category = excluded.category,
    description = excluded.description,
    metadata = excluded.metadata,
    updated_at = timezone('utc', now())
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
  if not coalesce((verification->>'allowed')::boolean, false) then
    return verification;
  end if;

  app_id_value := nullif(verification #>> '{app,id}', '')::uuid;
  if app_id_value is null then
    return jsonb_build_object('allowed', false, 'error', jsonb_build_object('code', 'app_missing', 'message', 'App could not be resolved.'));
  end if;

  if not exists (
    select 1 from public.memact_schema_definitions
    where app_id = app_id_value and schema_id = clean_schema_id
  ) then
    return jsonb_build_object('allowed', false, 'error', jsonb_build_object('code', 'schema_not_found', 'message', 'Schema definition not found.'));
  end if;

  insert into public.memact_subschema_definitions (
    app_id,
    schema_id,
    sub_schema_id,
    description,
    metadata,
    updated_at
  )
  values (
    app_id_value,
    clean_schema_id,
    clean_sub_schema_id,
    left(coalesce(description_input, ''), 500),
    coalesce(metadata_input, '{}'::jsonb),
    timezone('utc', now())
  )
  on conflict (app_id, schema_id, sub_schema_id)
  do update set
    description = excluded.description,
    metadata = excluded.metadata,
    updated_at = timezone('utc', now())
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
  if not coalesce((verification->>'allowed')::boolean, false) then
    return verification;
  end if;

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
  if not coalesce((verification->>'allowed')::boolean, false) then
    return verification;
  end if;

  app_id_value := nullif(verification #>> '{app,id}', '')::uuid;
  select * into schema_row
  from public.memact_schema_definitions
  where app_id = app_id_value and schema_id = clean_schema_id
  limit 1;

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
