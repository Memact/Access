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
    'product', 'permissioned_understanding',
    'tagline', 'Understand users'' digital activity.',
    'summary', 'Use approved activity categories to produce scoped context, not raw capture.',
    'scopes', to_jsonb((select scopes from clean)),
    'categories', to_jsonb((select categories from clean)),
    'category_algorithms', coalesce((select jsonb_agg(algorithm) from category_rows), '[]'::jsonb),
    'capture_plan', jsonb_build_object(
      'local_only_raw_capture', true,
      'allowed_inputs', coalesce((select jsonb_agg(distinct value) from category_rows, jsonb_array_elements_text(algorithm->'capture') value), '[]'::jsonb)
    ),
    'understanding_plan', jsonb_build_object(
      'outputs', coalesce((select jsonb_agg(distinct value) from category_rows, jsonb_array_elements_text(algorithm->'understand') value), '[]'::jsonb),
      'schema_packets', case when 'schema:write' = any((select scopes from clean)) then coalesce((select jsonb_agg(distinct value) from category_rows, jsonb_array_elements_text(algorithm->'schema') value), '[]'::jsonb) else '[]'::jsonb end,
      'graph_write', 'graph:write' = any((select scopes from clean)),
      'memory_write', 'memory:write' = any((select scopes from clean))
    ),
    'delivery_plan', jsonb_build_object(
      'summaries', 'memory:read_summary' = any((select scopes from clean)),
      'evidence_cards', 'memory:read_evidence' = any((select scopes from clean)),
      'graph_objects', 'memory:read_graph' = any((select scopes from clean))
    ),
    'storage_plan', jsonb_build_object(
      'default', jsonb_build_object('id', 'local-first-memory', 'label', 'Local-first memory', 'description', 'Capture packets and raw evidence stay local by default. Apps receive only verified understanding allowed by consent.'),
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
