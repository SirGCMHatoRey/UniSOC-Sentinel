import React from 'react'
import { useQuery } from '@tanstack/react-query'
import { getTopIPs } from '@/api/dashboard'
import LoadingSpinner from '@/components/common/LoadingSpinner'

const countryFlagEmoji = (code: string): string => {
  if (!code || code.length !== 2) return '🌐'
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
  if (error) return <div className="text-siem-red text-sm">Failed to load top IPs</div>

  const ips = data ?? []

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="text-gray-400 border-b border-siem-border">
            <th className="pb-2 text-left font-medium">#</th>
            <th className="pb-2 text-left font-medium">IP Address</th>
            <th className="pb-2 text-left font-medium">Country</th>
            <th className="pb-2 text-right font-medium">Events</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-siem-border">
          {ips.slice(0, 10).map((item, idx) => (
            <tr key={item.ip} className="hover:bg-siem-border/30 transition-colors">
              <td className="py-2 text-gray-500">{idx + 1}</td>
              <td className="py-2 font-mono text-siem-blue">{item.ip}</td>
              <td className="py-2 text-gray-300">
                <span className="mr-1">{countryFlagEmoji(item.country_code)}</span>
                {item.country}
              </td>
              <td className="py-2 text-right text-white font-medium">
                {item.count.toLocaleString()}
              </td>
            </tr>
          ))}
          {ips.length === 0 && (
            <tr>
              <td colSpan={4} className="py-4 text-center text-gray-500">No data</td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}

export default TopSourceIPs
