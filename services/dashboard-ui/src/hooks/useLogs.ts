import { useQuery } from '@tanstack/react-query'
import { getLogs } from '@/api/logs'
import { LogsQuery } from '@/types'

export function useLogs(query: LogsQuery = {}) {
  return useQuery({
    queryKey: ['logs', query],
    queryFn: () => getLogs(query),
    staleTime: 10_000,
  })
}
