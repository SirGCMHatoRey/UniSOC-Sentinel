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
  if (error) return <div className="text-threat text-sm">Failed to load auth data</div>

  const chartData = (data ?? []).map((d) => ({
    hour: format(new Date(d.timestamp), 'HH:mm'),
    value: d.value,
  }))

  return (
    <ResponsiveContainer width="100%" height={220}>
      <BarChart data={chartData} margin={{ top: 5, right: 10, left: 0, bottom: 5 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#263026" />
        <XAxis dataKey="hour" stroke="#7d8c7a" tick={{ fill: '#7d8c7a', fontSize: 11 }} />
        <YAxis stroke="#7d8c7a" tick={{ fill: '#7d8c7a', fontSize: 11 }} />
        <Tooltip
          contentStyle={{ backgroundColor: '#12160f', border: '1px solid #263026', borderRadius: 0 }}
          labelStyle={{ color: '#d7e0d3' }}
          itemStyle={{ color: '#ffcc66' }}
          formatter={(value: number) => [value, 'Failed Attempts']}
        />
        <Bar dataKey="value" fill="#ffcc66" name="Failed Attempts" radius={[0, 0, 0, 0]} />
      </BarChart>
    </ResponsiveContainer>
  )
}

export default FailedAuthAttempts
