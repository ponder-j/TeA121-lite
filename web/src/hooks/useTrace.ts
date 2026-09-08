import { useQuery } from '@tanstack/react-query';
import { api } from '../app/api-client';
export const useTrace = (runId: string) => useQuery({ queryKey: ['trace', runId], queryFn: () => api.listTrace(runId), enabled: Boolean(runId) });
