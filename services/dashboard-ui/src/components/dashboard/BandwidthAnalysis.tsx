import React from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts'
import { getBandwidth } from '@/api/dashboard'
import LoadingSpinner from '@/components/common/LoadingSpinner'
import { formatBytes } from '@/utils/format'
import { format } from 'date-fns'

interface BandwidthAnalysisProps {
  fromTs: string
  toTs: string
}

const BandwidthAnalysis: React.FC<BandwidthAnalysisProps> = ({ fromTs, toTs }) => {
  const { data, isLoading, error } = useQuery({
    queryKey: ['dashboard', 'bandwidth', fromTs, toTs],
    queryFn: () => getBandwidth(fromTs, toTs),
    refetchInterval: 60_000,
  })

  if (isLoading) return <div className="flex justify-center py-8"><LoadingSpinner /></div>
  if (error) return <div className="text-threat text-sm">Failed to load bandwidth data</div>

  const chartData = (data ?? []).map((d) => ({
    time: format(new Date(d.timestamp), 'HH:mm'),
    bytes: d.value,
  }))

  return (
    <ResponsiveContainer width="100%" height={220}>
      <AreaChart data={chartData} margin={{ top: 5, right: 10, left: 10, bottom: 5 }}>
        <defs>
          <linearGradient id="bwGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="#ffb454" stopOpacity={0.3} />
            <stop offset="95%" stopColor="#ffb454" stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid strokeDasharray="3 3" stroke="#263026" />
        <XAxis dataKey="time" stroke="#7d8c7a" tick={{ fill: '#7d8c7a', fontSize: 11 }} />
        <YAxis
          stroke="#7d8c7a"
          tick={{ fill: '#7d8c7a', fontSize: 11 }}
          tickFormatter={(v: number) => formatBytes(v)}
        />
        <Tooltip
          contentStyle={{ backgroundColor: '#12160f', border: '1px solid #263026', borderRadius: 0 }}
          labelStyle={{ color: '#d7e0d3' }}
          formatter={(value: number) => [formatBytes(value), 'Bandwidth']}
        />
        <Area
          type="monotone"
          dataKey="bytes"
          stroke="#ffb454"
          fill="url(#bwGrad)"
          strokeWidth={2}
          name="Bandwidth"
        />
      </AreaChart>
    </ResponsiveContainer>
  )
}

export default BandwidthAnalysis
