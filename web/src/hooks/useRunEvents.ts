import { useEffect, useRef } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { api } from '../app/api-client';
type RunEvent = { type: string; data: unknown };
export function useRunEvents(runId: string, enabled = true, onEvent?: (event: RunEvent) => void) {
  const client = useQueryClient();
  const eventHandler = useRef(onEvent);
  eventHandler.current = onEvent;
  useEffect(() => {
    if (!enabled || !runId) return;
    const refresh = (event: RunEvent) => {
      void client.invalidateQueries({ queryKey: ['run', runId] });
      eventHandler.current?.(event);
    };
    const poll = () => refresh({ type: 'poll', data: { run_id: runId } });
    const unsubscribe = api.subscribeRunEvents(runId, refresh);
    const timer = window.setInterval(poll, 3000);
    return () => { unsubscribe(); window.clearInterval(timer); };
  }, [runId, enabled, client]);
}
