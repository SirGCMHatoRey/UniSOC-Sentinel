import React from 'react'
import { useQuery } from '@tanstack/react-query'
import { getWirelessActivity } from '@/api/dashboard'
import LoadingSpinner from '@/components/common/LoadingSpinner'
import { formatDate } from '@/utils/format'

const WirelessActivity: React.FC = () => {
  const { data, isLoading, error } = useQuery({
    queryKey: ['dashboard', 'wireless-activity'],
    queryFn: getWirelessActivity,
    refetchInterval: 60_000,
  })

  if (isLoading) return <div className="flex justify-center py-4"><LoadingSpinner /></div>
  if (error) return <div className="text-siem-red text-sm">Failed to load wireless activity</div>

  const events = data ?? []

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="text-gray-400 border-b border-siem-border">
            <th className="pb-2 text-left font-medium">Timestamp</th>
            <th className="pb-2 text-left font-medium">MAC</th>
            <th className="pb-2 text-left font-medium">SSID</th>
            <th className="pb-2 text-left font-medium">Event</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-siem-border">
          {events.slice(0, 10).map((e, i) => (
            <tr key={i} className="hover:bg-siem-border/30 transition-colors">
              <td className="py-2 text-gray-400 text-xs">{formatDate(e.timestamp)}</td>
              <td className="py-2 font-mono text-gray-300 text-xs">{e.mac}</td>
              <td className="py-2 text-white">{e.ssid}</td>
              <td className="py-2">
                <span
                  className={`text-xs px-2 py-0.5 rounded-full ${
                    e.event_type === 'association'
                      ? 'bg-siem-green/20 text-siem-green'
                      : 'bg-siem-orange/20 text-siem-orange'
                  }`}
                >
                  {e.event_type}
                </span>
              </td>
            </tr>
          ))}
          {events.length === 0 && (
            <tr>
              <td colSpan={4} className="py-4 text-center text-gray-500">No wireless events</td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}

export default WirelessActivity
