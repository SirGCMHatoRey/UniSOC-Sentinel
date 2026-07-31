import React from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from 'recharts'
import { getFirewallActivity } from '@/api/dashboard'
import { timeRangeToParams } from '@/utils/time'
import LoadingSpinner from '@/components/common/LoadingSpinner'
import { format } from 'date-fns'

interface FirewallActivityProps {
  fromTs: string
  toTs: string
}

const FirewallActivity: React.FC<FirewallActivityProps> = ({ fromTs, toTs }) => {
  const { data, isLoading, error } = useQuery({
    queryKey: ['dashboard', 'firewall-activity', fromTs, toTs],
    queryFn: () => getFirewallActivity(fromTs, toTs),
    refetchInterval: 60_000,
  })

  if (isLoading) return <div className="flex justify-center py-8"><LoadingSpinner /></div>
  if (error) return <div className="text-siem-red text-sm">Failed to load firewall activity</div>

  const chartData = (data ?? []).map((d) => ({
    time: format(new Date(d.timestamp), 'HH:mm'),
    allow: d.allow,
    deny: d.deny,
  }))

  return (
    <ResponsiveContainer width="100%" height={220}>
      <AreaChart data={chartData} margin={{ top: 5, right: 10, left: 0, bottom: 5 }}>
        <defs>
          <linearGradient id="allowGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="#22c55e" stopOpacity={0.3} />
            <stop offset="95%" stopColor="#22c55e" stopOpacity={0} />
          </linearGradient>
          <linearGradient id="denyGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
            <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid strokeDasharray="3 3" stroke="#2a2d3a" />
        <XAxis dataKey="time" stroke="#6b7280" tick={{ fill: '#9ca3af', fontSize: 11 }} />
        <YAxis stroke="#6b7280" tick={{ fill: '#9ca3af', fontSize: 11 }} />
        <Tooltip
          contentStyle={{ backgroundColor: '#1a1d27', border: '1px solid #2a2d3a', borderRadius: 6 }}
          labelStyle={{ color: '#e5e7eb' }}
          itemStyle={{ color: '#d1d5db' }}
        />
        <Legend wrapperStyle={{ color: '#9ca3af', fontSize: 12 }} />
        <Area type="monotone" dataKey="allow" stroke="#22c55e" fill="url(#allowGrad)" strokeWidth={2} name="Allow" />
        <Area type="monotone" dataKey="deny" stroke="#ef4444" fill="url(#denyGrad)" strokeWidth={2} name="Deny" />
      </AreaChart>
    </ResponsiveContainer>
  )
}

export default FirewallActivity

export { timeRangeToParams }
