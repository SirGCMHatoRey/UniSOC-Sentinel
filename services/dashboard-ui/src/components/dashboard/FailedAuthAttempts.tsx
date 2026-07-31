import React from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts'
import client from '@/api/client'
import { TimeSeriesPoint } from '@/types'
import LoadingSpinner from '@/components/common/LoadingSpinner'
import { format } from 'date-fns'

interface FailedAuthAttemptsProps {
  fromTs: string
  toTs: string
}

async function getFailedAuth(fromTs: string, toTs: string): Promise<TimeSeriesPoint[]> {
  const response = await client.get<TimeSeriesPoint[]>('/dashboard/failed-auth', {
    params: { from_ts: fromTs, to_ts: toTs },
  })
  return response.data
}

const FailedAuthAttempts: React.FC<FailedAuthAttemptsProps> = ({ fromTs, toTs }) => {
  const { data, isLoading, error } = useQuery({
    queryKey: ['dashboard', 'failed-auth', fromTs, toTs],
    queryFn: () => getFailedAuth(fromTs, toTs),
    refetchInterval: 60_000,
  })

  if (isLoading) return <div className="flex justify-center py-8"><LoadingSpinner /></div>
  if (error) return <div className="text-siem-red text-sm">Failed to load auth data</div>

  const chartData = (data ?? []).map((d) => ({
    hour: format(new Date(d.timestamp), 'HH:mm'),
    value: d.value,
  }))

  return (
    <ResponsiveContainer width="100%" height={220}>
      <BarChart data={chartData} margin={{ top: 5, right: 10, left: 0, bottom: 5 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#2a2d3a" />
        <XAxis dataKey="hour" stroke="#6b7280" tick={{ fill: '#9ca3af', fontSize: 11 }} />
        <YAxis stroke="#6b7280" tick={{ fill: '#9ca3af', fontSize: 11 }} />
        <Tooltip
          contentStyle={{ backgroundColor: '#1a1d27', border: '1px solid #2a2d3a', borderRadius: 6 }}
          labelStyle={{ color: '#e5e7eb' }}
          itemStyle={{ color: '#eab308' }}
          formatter={(value: number) => [value, 'Failed Attempts']}
        />
        <Bar dataKey="value" fill="#eab308" name="Failed Attempts" radius={[2, 2, 0, 0]} />
      </BarChart>
    </ResponsiveContainer>
  )
}

export default FailedAuthAttempts
