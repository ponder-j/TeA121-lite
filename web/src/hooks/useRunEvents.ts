import { useEffect } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { api } from '../app/api-client';
export function useRunEvents(runId: string, enabled = true) { const client = useQueryClient(); useEffect(() => { if (!enabled || !runId) return; const refresh = () => { void client.invalidateQueries({ queryKey: ['run', runId] }); }; const unsubscribe = api.subscribeRunEvents(runId, refresh); const poll = window.setInterval(refresh, 3000); return () => { unsubscribe(); window.clearInterval(poll); }; }, [runId, enabled, client]); }
