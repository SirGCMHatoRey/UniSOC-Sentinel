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
  if (error) return <div className="text-threat text-sm">Failed to load threat intel data</div>

  const matches = data ?? []

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="text-ink-dim border-b border-hairline uppercase text-xs tracking-wide">
            <th className="pb-2 text-left font-medium">IP</th>
            <th className="pb-2 text-left font-medium">Feed</th>
            <th className="pb-2 text-left font-medium">Country</th>
            <th className="pb-2 text-right font-medium">Score</th>
            <th className="pb-2 text-right font-medium">Time</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-hairline">
          {matches.slice(0, 10).map((m, i) => (
            <tr key={i} className="hover:bg-hairline/30 transition-colors">
              <td className="py-2 text-threat">{m.ip}</td>
              <td className="py-2 text-ink-dim">{m.feed}</td>
              <td className="py-2 text-ink-dim">{m.country}</td>
              <td className="py-2 text-right">
                <span
                  className={`text-xs font-bold tabular-nums ${
                    m.score >= 80
                      ? 'text-threat'
                      : m.score >= 50
                      ? 'text-warn'
                      : 'text-ink-dim'
                  }`}
                >
                  {m.score}
                </span>
              </td>
              <td className="py-2 text-right text-ink-dim text-xs">
                {formatRelativeTime(m.timestamp)}
              </td>
            </tr>
          ))}
          {matches.length === 0 && (
            <tr>
              <td colSpan={5} className="py-4 text-center text-ink-dim">No matches</td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}

export default ThreatIntelMatches
