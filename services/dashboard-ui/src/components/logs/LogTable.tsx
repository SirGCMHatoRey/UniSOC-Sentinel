import React, { useState } from 'react'
import { ECSEvent } from '@/types'
import { formatDate } from '@/utils/format'
import SeverityBadge from '@/components/common/SeverityBadge'
import LogDetail from './LogDetail'

interface LogTableProps {
  events: ECSEvent[]
  total: number
  page: number
  size: number
  onPageChange: (page: number) => void
  isLoading: boolean
}

const LogTable: React.FC<LogTableProps> = ({
  events,
  total,
  page,
  size,
  onPageChange,
  isLoading,
}) => {
  const [selected, setSelected] = useState<ECSEvent | null>(null)

  const totalPages = Math.ceil(total / size)

  return (
    <>
      <div className="overflow-x-auto border border-hairline">
        <table className="w-full text-sm">
          <thead className="bg-hairline/30">
            <tr className="text-ink-dim uppercase text-xs tracking-wide">
              <th className="px-3 py-3 text-left font-medium">Timestamp</th>
              <th className="px-3 py-3 text-left font-medium">Dataset</th>
              <th className="px-3 py-3 text-left font-medium">Source IP</th>
              <th className="px-3 py-3 text-left font-medium">Destination</th>
              <th className="px-3 py-3 text-left font-medium">Protocol</th>
              <th className="px-3 py-3 text-left font-medium">Severity</th>
              <th className="px-3 py-3 text-left font-medium">Outcome</th>
              <th className="px-3 py-3 text-left font-medium">Message</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-hairline bg-panel">
            {isLoading ? (
              <tr>
                <td colSpan={8} className="py-8 text-center text-ink-dim">Loading...</td>
              </tr>
            ) : events.length === 0 ? (
              <tr>
                <td colSpan={8} className="py-8 text-center text-ink-dim">No events found</td>
              </tr>
            ) : (
              events.map((event) => (
                <tr
                  key={event.event.id}
                  onClick={() => setSelected(event)}
                  className="hover:bg-hairline/40 cursor-pointer transition-colors"
                >
                  <td className="px-3 py-2 text-ink-dim text-xs whitespace-nowrap">
                    {formatDate(event['@timestamp'])}
                  </td>
                  <td className="px-3 py-2 text-ink-dim">
                    <span className="px-1.5 py-0.5 border border-hairline text-xs text-ink-dim">
                      {event.event.dataset}
                    </span>
                  </td>
                  <td className="px-3 py-2 text-ink text-xs">
                    {event.source.ip ?? '—'}
                  </td>
                  <td className="px-3 py-2 text-ink-dim text-xs">
                    {event.destination.ip ? `${event.destination.ip}:${event.destination.port ?? ''}` : '—'}
                  </td>
                  <td className="px-3 py-2 text-ink-dim text-xs">
                    {event.network.protocol ?? '—'}
                  </td>
                  <td className="px-3 py-2">
                    <SeverityBadge severity={String(event.event.severity)} />
                  </td>
                  <td className="px-3 py-2">
                    <span
                      className={`text-xs px-1.5 py-0.5 border ${
                        event.event.outcome === 'success'
                          ? 'border-ok/40 text-ok'
                          : event.event.outcome === 'failure'
                          ? 'border-threat/40 text-threat'
                          : 'border-hairline text-ink-dim'
                      }`}
                    >
                      {event.event.outcome}
                    </span>
                  </td>
                  <td className="px-3 py-2 text-ink-dim text-xs max-w-xs truncate">
                    {event.message}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      <div className="flex items-center justify-between mt-3 text-sm text-ink-dim">
        <span>
          Showing {Math.min((page - 1) * size + 1, total)}–{Math.min(page * size, total)} of{' '}
          {total.toLocaleString()} events
        </span>
        <div className="flex gap-2">
          <button
            onClick={() => onPageChange(page - 1)}
            disabled={page <= 1}
            className="px-3 py-1 bg-panel border border-hairline disabled:opacity-40 hover:border-signal transition-colors"
          >
            Prev
          </button>
          <span className="px-3 py-1 text-ink-dim">
            {page} / {totalPages}
          </span>
          <button
            onClick={() => onPageChange(page + 1)}
            disabled={page >= totalPages}
            className="px-3 py-1 bg-panel border border-hairline disabled:opacity-40 hover:border-signal transition-colors"
          >
            Next
          </button>
        </div>
      </div>

      {selected && <LogDetail event={selected} onClose={() => setSelected(null)} />}
    </>
  )
}

export default LogTable
