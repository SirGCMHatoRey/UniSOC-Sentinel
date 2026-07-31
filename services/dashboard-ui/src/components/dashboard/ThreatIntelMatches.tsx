import React from 'react'
import { useQuery } from '@tanstack/react-query'
import { getThreatIntelMatches } from '@/api/dashboard'
import LoadingSpinner from '@/components/common/LoadingSpinner'
import { formatRelativeTime } from '@/utils/format'

const ThreatIntelMatches: React.FC = () => {
  const { data, isLoading, error } = useQuery({
    queryKey: ['dashboard', 'threat-intel-matches'],
    queryFn: getThreatIntelMatches,
    refetchInterval: 60_000,
  })

  if (isLoading) return <div className="flex justify-center py-4"><LoadingSpinner /></div>
  if (error) return <div className="text-siem-red text-sm">Failed to load threat intel data</div>

  const matches = data ?? []

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="text-gray-400 border-b border-siem-border">
            <th className="pb-2 text-left font-medium">IP</th>
            <th className="pb-2 text-left font-medium">Feed</th>
            <th className="pb-2 text-left font-medium">Country</th>
            <th className="pb-2 text-right font-medium">Score</th>
            <th className="pb-2 text-right font-medium">Time</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-siem-border">
          {matches.slice(0, 10).map((m, i) => (
            <tr key={i} className="hover:bg-siem-border/30 transition-colors">
              <td className="py-2 font-mono text-siem-red">{m.ip}</td>
              <td className="py-2 text-gray-300">{m.feed}</td>
              <td className="py-2 text-gray-400">{m.country}</td>
              <td className="py-2 text-right">
                <span
                  className={`text-xs font-bold ${
                    m.score >= 80
                      ? 'text-siem-red'
                      : m.score >= 50
                      ? 'text-siem-orange'
                      : 'text-siem-yellow'
                  }`}
                >
                  {m.score}
                </span>
              </td>
              <td className="py-2 text-right text-gray-500 text-xs">
                {formatRelativeTime(m.timestamp)}
              </td>
            </tr>
          ))}
          {matches.length === 0 && (
            <tr>
              <td colSpan={5} className="py-4 text-center text-gray-500">No matches</td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}

export default ThreatIntelMatches
