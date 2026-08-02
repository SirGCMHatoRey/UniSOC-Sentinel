import React from 'react'
import { useQuery } from '@tanstack/react-query'
import { getTopIPs } from '@/api/dashboard'
import LoadingSpinner from '@/components/common/LoadingSpinner'

const countryFlagEmoji = (code: string): string => {
  if (!code || code.length !== 2) return '—'
  const offset = 0x1f1e6
  const chars = code
    .toUpperCase()
    .split('')
    .map((c) => String.fromCodePoint(c.charCodeAt(0) - 65 + offset))
  return chars.join('')
}

const TopSourceIPs: React.FC = () => {
  const { data, isLoading, error } = useQuery({
    queryKey: ['dashboard', 'top-ips'],
    queryFn: getTopIPs,
    refetchInterval: 60_000,
  })

  if (isLoading) return <div className="flex justify-center py-4"><LoadingSpinner /></div>
  if (error) return <div className="text-threat text-sm">Failed to load top IPs</div>

  const ips = data ?? []

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="text-ink-dim border-b border-hairline uppercase text-xs tracking-wide">
            <th className="pb-2 text-left font-medium">#</th>
            <th className="pb-2 text-left font-medium">IP Address</th>
            <th className="pb-2 text-left font-medium">Country</th>
            <th className="pb-2 text-right font-medium">Events</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-hairline">
          {ips.slice(0, 10).map((item, idx) => (
            <tr key={item.ip} className="hover:bg-hairline/30 transition-colors">
              <td className="py-2 text-ink-dim">{idx + 1}</td>
              <td className="py-2 text-ink">{item.ip}</td>
              <td className="py-2 text-ink-dim">
                <span className="mr-1">{countryFlagEmoji(item.country_code)}</span>
                {item.country}
              </td>
              <td className="py-2 text-right text-ink font-medium tabular-nums">
                {item.count.toLocaleString()}
              </td>
            </tr>
          ))}
          {ips.length === 0 && (
            <tr>
              <td colSpan={4} className="py-4 text-center text-ink-dim">No data</td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}

export default TopSourceIPs
