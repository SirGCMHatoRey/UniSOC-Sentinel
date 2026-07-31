import React from 'react'
import { useQuery } from '@tanstack/react-query'
import { getStats } from '@/api/dashboard'
import StatCard from '@/components/common/StatCard'
import LoadingSpinner from '@/components/common/LoadingSpinner'

const ThreatOverview: React.FC = () => {
  const { data, isLoading, error } = useQuery({
    queryKey: ['dashboard', 'stats'],
    queryFn: getStats,
    refetchInterval: 60_000,
  })

  if (isLoading) {
    return (
      <div className="col-span-full flex justify-center py-8">
        <LoadingSpinner />
      </div>
    )
  }

  if (error || !data) {
    return (
      <div className="col-span-full text-center text-siem-red py-4">
        Failed to load stats
      </div>
    )
  }

  return (
    <>
      <StatCard
        title="Total Events"
        value={data.total_events}
        variant="blue"
        icon="📊"
      />
      <StatCard
        title="Active Alerts"
        value={data.total_alerts}
        variant="orange"
        icon="⚡"
      />
      <StatCard
        title="Blocked Connections"
        value={data.blocked_connections}
        variant="red"
        icon="🚫"
      />
      <StatCard
        title="Auth Failures"
        value={data.auth_failures}
        variant="yellow"
        icon="🔐"
      />
      <StatCard
        title="Active VPN Sessions"
        value={data.active_vpn_sessions}
        variant="green"
        icon="🔒"
      />
      <StatCard
        title="Threat Intel Matches"
        value={data.threat_intel_matches}
        variant="red"
        icon="🎯"
      />
    </>
  )
}

export default ThreatOverview
