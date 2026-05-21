create table if not exists public.memact_capture_events (
  id uuid primary key default gen_random_uuid(),
  app_id uuid,
  connection_id uuid,
  event_type text not null,
  category text not null,
  payload jsonb not null default '{}'::jsonb,
  evidence jsonb not null default '{}'::jsonb,
  metadata jsonb not null default '{}'::jsonb,
  occurred_at timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists public.memact_feature_registry (
  feature_id text primary key,
  name text not null,
  description text not null default '',
  required_scopes text[] not null default array[]::text[],
  required_schema_types text[] not null default array[]::text[],
  enabled boolean not null default true,
  created_at timestamptz not null default now()
);

create table if not exists public.memact_feature_runs (
  id uuid primary key default gen_random_uuid(),
  feature_id text not null,
  app_id uuid,
  connection_id uuid,
  status text not null,
  output jsonb not null default '{}'::jsonb,
  errors jsonb not null default '[]'::jsonb,
  created_at timestamptz not null default now()
);

create table if not exists public.memact_schema_packets (
  id uuid primary key default gen_random_uuid(),
  app_id uuid,
  packet_id text,
  category text,
  schema_type text,
  confidence numeric,
  summary jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create table if not exists public.memact_memory_records (
  id uuid primary key default gen_random_uuid(),
  app_id uuid,
  memory_id text,
  memory_type text,
  subject text,
  confidence numeric,
  summary jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create table if not exists public.memact_usage_events (
  id uuid primary key default gen_random_uuid(),
  app_id uuid,
  action text not null,
  details jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);
