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
