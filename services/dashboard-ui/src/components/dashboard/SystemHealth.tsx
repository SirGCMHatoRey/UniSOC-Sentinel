import React from 'react'
import { useQuery } from '@tanstack/react-query'
import { getSystemHealth } from '@/api/dashboard'
import LoadingSpinner from '@/components/common/LoadingSpinner'
import { SystemHealth as SystemHealthType } from '@/types'

type HealthStatus = 'healthy' | 'degraded' | 'down'

const statusDot: Record<HealthStatus, string> = {
  healthy: 'bg-siem-green',
  degraded: 'bg-siem-yellow',
  down: 'bg-siem-red',
}

const statusLabel: Record<HealthStatus, string> = {
  healthy: 'Healthy',
  degraded: 'Degraded',
  down: 'Down',
}

const statusTextColor: Record<HealthStatus, string> = {
  healthy: 'text-siem-green',
  degraded: 'text-siem-yellow',
  down: 'text-siem-red',
}

interface ServiceRowProps {
  name: string
  status: HealthStatus
}

const ServiceRow: React.FC<ServiceRowProps> = ({ name, status }) => (
  <div className="flex items-center justify-between py-2 border-b border-siem-border last:border-0">
    <div className="flex items-center gap-2">
      <span className={`w-2.5 h-2.5 rounded-full flex-shrink-0 ${statusDot[status]}`} />
      <span className="text-sm text-gray-300">{name}</span>
    </div>
    <span className={`text-xs font-medium ${statusTextColor[status]}`}>
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
  if (error) return <div className="text-siem-red text-sm">Failed to load system health</div>

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
