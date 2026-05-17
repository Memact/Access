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
    'intent:predict'
  ]::text[];
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
      'memory:read_summary',
      'intent:predict'
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
      'memory:read_summary', jsonb_build_object('label', 'Read context summaries', 'description', 'Receive compact summaries of approved user context.', 'grantsGraphRead', false),
      'memory:read_evidence', jsonb_build_object('label', 'Read evidence cards', 'description', 'Receive approved evidence snippets that explain the context.', 'grantsGraphRead', false, 'sensitive', true),
      'memory:read_graph', jsonb_build_object('label', 'Read context graph', 'description', 'Receive permitted nodes and edges about approved user context.', 'grantsGraphRead', true, 'sensitive', true),
      'intent:predict', jsonb_build_object('label', 'Predict intent', 'description', 'Ask Memact for evidence-backed intent hypotheses from approved activity.', 'grantsGraphRead', false, 'sensitive', true)
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
    )
  );
$$;

notify pgrst, 'reload schema';
