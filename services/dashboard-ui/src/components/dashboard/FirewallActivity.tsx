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
  if (error) return <div className="text-threat text-sm">Failed to load firewall activity</div>

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
            <stop offset="5%" stopColor="#5eff8f" stopOpacity={0.3} />
            <stop offset="95%" stopColor="#5eff8f" stopOpacity={0} />
          </linearGradient>
          <linearGradient id="denyGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="#ff4d4d" stopOpacity={0.3} />
            <stop offset="95%" stopColor="#ff4d4d" stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid strokeDasharray="3 3" stroke="#263026" />
        <XAxis dataKey="time" stroke="#7d8c7a" tick={{ fill: '#7d8c7a', fontSize: 11 }} />
        <YAxis stroke="#7d8c7a" tick={{ fill: '#7d8c7a', fontSize: 11 }} />
        <Tooltip
          contentStyle={{ backgroundColor: '#12160f', border: '1px solid #263026', borderRadius: 0 }}
          labelStyle={{ color: '#d7e0d3' }}
          itemStyle={{ color: '#d7e0d3' }}
        />
        <Legend wrapperStyle={{ color: '#7d8c7a', fontSize: 12 }} />
        <Area type="monotone" dataKey="allow" stroke="#5eff8f" fill="url(#allowGrad)" strokeWidth={2} name="Allow" />
        <Area type="monotone" dataKey="deny" stroke="#ff4d4d" fill="url(#denyGrad)" strokeWidth={2} name="Deny" />
      </AreaChart>
    </ResponsiveContainer>
  )
}

export default FirewallActivity

export { timeRangeToParams }
