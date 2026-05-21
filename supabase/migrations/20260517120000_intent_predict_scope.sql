-- Legacy migration slot kept so existing migration history remains stable.
-- Intent prediction is no longer a core Access scope.
notify pgrst, 'reload schema';
