import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { getAlerts, acknowledgeAlert } from '@/api/alerts'
import { AlertsQuery } from '@/types'

export function useAlerts(query: AlertsQuery = {}) {
  return useQuery({
    queryKey: ['alerts', query],
    queryFn: () => getAlerts(query),
    refetchInterval: 30_000,
  })
}

export function useUnacknowledgedCount() {
  return useQuery({
    queryKey: ['alerts', 'unacknowledged-count'],
    queryFn: () => getAlerts({ acknowledged: false, size: 1 }),
    refetchInterval: 30_000,
    select: (data) => data.total,
  })
}

export function useAcknowledgeAlert() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => acknowledgeAlert(id),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['alerts'] })
    },
  })
}
