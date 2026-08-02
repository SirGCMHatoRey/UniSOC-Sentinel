import React from 'react'
import { useQuery } from '@tanstack/react-query'
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts'
import { getFirewallActivity } from '@/api/dashboard'
import { format } from 'date-fns'

interface BlockedConnectionsProps {
  fromTs: string
  toTs: string
}

const BlockedConnections: React.FC<BlockedConnectionsProps> = ({ fromTs, toTs }) => {
  const { data, isLoading } = useQuery({
    queryKey: ['dashboard', 'firewall-activity', fromTs, toTs],
    queryFn: () => getFirewallActivity(fromTs, toTs),
    refetchInterval: 60_000,
  })

  const total = (data ?? []).reduce((sum, d) => sum + d.deny, 0)
  const chartData = (data ?? []).map((d) => ({
    time: format(new Date(d.timestamp), 'HH:mm'),
    deny: d.deny,
  }))

  return (
    <div>
      <div className="mb-3">
        {isLoading ? (
          <p className="text-2xl font-bold text-threat">...</p>
        ) : (
          <p className="text-3xl font-bold text-threat tabular-nums">{total.toLocaleString()}</p>
        )}
        <p className="text-xs text-ink-dim mt-0.5 uppercase tracking-wide">blocked in selected period</p>
      </div>
      <ResponsiveContainer width="100%" height={80}>
        <LineChart data={chartData} margin={{ top: 2, right: 0, left: 0, bottom: 2 }}>
          <XAxis dataKey="time" hide />
          <YAxis hide />
          <Tooltip
            contentStyle={{ backgroundColor: '#12160f', border: '1px solid #263026', borderRadius: 0, fontSize: 11 }}
            labelStyle={{ color: '#d7e0d3' }}
            itemStyle={{ color: '#ff4d4d' }}
          />
          <Line type="monotone" dataKey="deny" stroke="#ff4d4d" strokeWidth={2} dot={false} name="Blocked" />
        </LineChart>
      </ResponsiveContainer>
    </div>
  )
}

export default BlockedConnections
