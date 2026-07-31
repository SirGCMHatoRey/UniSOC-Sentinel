import React from 'react'
import { useQuery } from '@tanstack/react-query'
import { getVPNSessions } from '@/api/dashboard'
import LoadingSpinner from '@/components/common/LoadingSpinner'
import { formatRelativeTime } from '@/utils/format'

const VPNSessions: React.FC = () => {
  const { data, isLoading, error } = useQuery({
    queryKey: ['dashboard', 'vpn-sessions'],
    queryFn: getVPNSessions,
    refetchInterval: 60_000,
  })

  if (isLoading) return <div className="flex justify-center py-4"><LoadingSpinner /></div>
  if (error) return <div className="text-siem-red text-sm">Failed to load VPN sessions</div>

  const sessions = data ?? []

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="text-gray-400 border-b border-siem-border">
            <th className="pb-2 text-left font-medium">User</th>
            <th className="pb-2 text-left font-medium">Source IP</th>
            <th className="pb-2 text-left font-medium">Country</th>
            <th className="pb-2 text-right font-medium">Connected</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-siem-border">
          {sessions.map((s, i) => (
            <tr key={i} className="hover:bg-siem-border/30 transition-colors">
              <td className="py-2 text-white">{s.user}</td>
              <td className="py-2 font-mono text-siem-blue">{s.source_ip}</td>
              <td className="py-2 text-gray-300">{s.country}</td>
              <td className="py-2 text-right text-gray-400 text-xs">
                {formatRelativeTime(s.connected_at)}
              </td>
            </tr>
          ))}
          {sessions.length === 0 && (
            <tr>
              <td colSpan={4} className="py-4 text-center text-gray-500">No active sessions</td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}

export default VPNSessions
