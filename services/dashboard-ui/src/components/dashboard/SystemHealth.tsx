import React from 'react'
import { useQuery } from '@tanstack/react-query'
import { getSystemHealth } from '@/api/dashboard'
import LoadingSpinner from '@/components/common/LoadingSpinner'
import { SystemHealth as SystemHealthType } from '@/types'

type HealthStatus = 'healthy' | 'degraded' | 'down'

const statusDot: Record<HealthStatus, string> = {
  healthy: 'bg-ok',
  degraded: 'bg-warn',
  down: 'bg-threat',
}

const statusLabel: Record<HealthStatus, string> = {
  healthy: 'Healthy',
  degraded: 'Degraded',
  down: 'Down',
}

const statusTextColor: Record<HealthStatus, string> = {
  healthy: 'text-ok',
  degraded: 'text-warn',
  down: 'text-threat',
}

interface ServiceRowProps {
  name: string
  status: HealthStatus
}

const ServiceRow: React.FC<ServiceRowProps> = ({ name, status }) => (
  <div className="flex items-center justify-between py-2 border-b border-hairline last:border-0">
    <div className="flex items-center gap-2">
      <span
        className={`w-2 h-2 rounded-full flex-shrink-0 ${statusDot[status]} ${
          status === 'down' ? 'animate-pulse-dot' : ''
        }`}
      />
      <span className="text-sm text-ink">{name}</span>
    </div>
    <span className={`text-xs font-medium uppercase tracking-wide ${statusTextColor[status]}`}>
      {statusLabel[status]}
    </span>
  </div>
)

const SystemHealth: React.FC = () => {
  const { data, isLoading, error } = useQuery({
    queryKey: ['dashboard', 'system-health'],
    queryFn: getSystemHealth,
    refetchInterval: 30_000,
  })

  if (isLoading) return <div className="flex justify-center py-4"><LoadingSpinner /></div>
  if (error) return <div className="text-threat text-sm">Failed to load system health</div>

  if (!data) return null

  const services: Array<{ name: string; key: keyof SystemHealthType }> = [
    { name: 'OpenSearch', key: 'opensearch' },
    { name: 'Redis', key: 'redis' },
    { name: 'PostgreSQL', key: 'postgresql' },
    { name: 'Pipeline', key: 'pipeline' },
  ]

  return (
    <div>
      {services.map((s) => (
        <ServiceRow key={s.key} name={s.name} status={data[s.key] as HealthStatus} />
      ))}
    </div>
  )
}

export default SystemHealth
