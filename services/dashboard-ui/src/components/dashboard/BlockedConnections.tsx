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
          <p className="text-2xl font-bold text-siem-red">...</p>
        ) : (
          <p className="text-3xl font-bold text-siem-red">{total.toLocaleString()}</p>
        )}
        <p className="text-xs text-gray-500 mt-0.5">blocked in selected period</p>
      </div>
      <ResponsiveContainer width="100%" height={80}>
        <LineChart data={chartData} margin={{ top: 2, right: 0, left: 0, bottom: 2 }}>
          <XAxis dataKey="time" hide />
          <YAxis hide />
          <Tooltip
            contentStyle={{ backgroundColor: '#1a1d27', border: '1px solid #2a2d3a', borderRadius: 4, fontSize: 11 }}
            labelStyle={{ color: '#e5e7eb' }}
            itemStyle={{ color: '#ef4444' }}
          />
          <Line type="monotone" dataKey="deny" stroke="#ef4444" strokeWidth={2} dot={false} name="Blocked" />
        </LineChart>
      </ResponsiveContainer>
    </div>
  )
}

export default BlockedConnections
