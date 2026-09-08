import { useQuery } from '@tanstack/react-query';
import { api } from '../app/api-client';
export const useRun = (runId: string) => useQuery({ queryKey: ['run', runId], queryFn: () => api.getRun(runId), enabled: Boolean(runId) });
