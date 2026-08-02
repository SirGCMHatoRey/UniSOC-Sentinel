import React from 'react'
import { ECSEvent } from '@/types'
import { formatDate } from '@/utils/format'
import SeverityBadge from '@/components/common/SeverityBadge'

interface LogDetailProps {
  event: ECSEvent
  onClose: () => void
}

const LogDetail: React.FC<LogDetailProps> = ({ event, onClose }) => {
  return (
    <div className="fixed inset-0 z-50 flex justify-end" role="dialog" aria-modal="true">
      <div
        className="fixed inset-0 bg-void/70 backdrop-blur-sm"
        onClick={onClose}
        aria-hidden="true"
      />
      <div className="relative w-full max-w-2xl bg-panel border-l border-hairline flex flex-col shadow-2xl overflow-hidden">
        <div className="flex items-center justify-between px-6 py-4 border-b border-hairline flex-shrink-0">
          <div className="flex items-center gap-3">
            <h2 className="text-lg font-semibold text-ink">Log Detail</h2>
            <SeverityBadge severity={String(event.event.severity)} />
          </div>
          <button
            onClick={onClose}
            className="text-ink-dim hover:text-ink text-xl leading-none p-1"
            aria-label="Close"
          >
            ×
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-6 space-y-4">
          {/* Key fields */}
          <div className="grid grid-cols-2 gap-3 text-sm">
            <div className="col-span-2">
              <span className="text-ink-dim text-xs uppercase tracking-wide">Timestamp</span>
              <p className="text-ink mt-0.5">{formatDate(event['@timestamp'])}</p>
            </div>
            <div>
              <span className="text-ink-dim text-xs uppercase tracking-wide">Dataset</span>
              <p className="text-ink mt-0.5">{event.event.dataset}</p>
            </div>
            <div>
              <span className="text-ink-dim text-xs uppercase tracking-wide">Outcome</span>
              <p className="text-ink mt-0.5">{event.event.outcome}</p>
            </div>
            <div>
              <span className="text-ink-dim text-xs uppercase tracking-wide">Source IP</span>
              <p className="text-ink mt-0.5">{event.source.ip ?? 'N/A'}</p>
            </div>
            <div>
              <span className="text-ink-dim text-xs uppercase tracking-wide">Source Port</span>
              <p className="text-ink mt-0.5">{event.source.port ?? 'N/A'}</p>
            </div>
            <div>
              <span className="text-ink-dim text-xs uppercase tracking-wide">Destination IP</span>
              <p className="text-ink mt-0.5">{event.destination.ip ?? 'N/A'}</p>
            </div>
            <div>
              <span className="text-ink-dim text-xs uppercase tracking-wide">Destination Port</span>
              <p className="text-ink mt-0.5">{event.destination.port ?? 'N/A'}</p>
            </div>
            <div>
              <span className="text-ink-dim text-xs uppercase tracking-wide">Protocol</span>
              <p className="text-ink mt-0.5">{event.network.protocol ?? 'N/A'}</p>
            </div>
            <div>
              <span className="text-ink-dim text-xs uppercase tracking-wide">Hostname</span>
              <p className="text-ink mt-0.5">{event.host.hostname ?? 'N/A'}</p>
            </div>
            {event.user.name && (
              <div>
                <span className="text-ink-dim text-xs uppercase tracking-wide">User</span>
                <p className="text-ink mt-0.5">{event.user.name}</p>
              </div>
            )}
            {event.source.geo && (
              <div>
                <span className="text-ink-dim text-xs uppercase tracking-wide">Geo</span>
                <p className="text-ink mt-0.5">
                  {event.source.geo.city_name}, {event.source.geo.country_name}
                </p>
              </div>
            )}
          </div>

          <div>
            <span className="text-ink-dim text-xs uppercase tracking-wide">Message</span>
            <p className="text-ink text-sm mt-1 leading-relaxed">{event.message}</p>
          </div>

          {event.tags.length > 0 && (
            <div>
              <span className="text-ink-dim text-xs uppercase tracking-wide">Tags</span>
              <div className="flex flex-wrap gap-1 mt-1">
                {event.tags.map((t) => (
                  <span key={t} className="px-2 py-0.5 text-xs border border-hairline text-ink-dim">
                    {t}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Raw JSON */}
          <div>
            <span className="text-ink-dim text-xs uppercase tracking-wide">Raw ECS Event</span>
            <pre className="mt-1 bg-void border border-hairline p-3 text-xs text-ink-dim overflow-x-auto leading-relaxed">
              {JSON.stringify(event, null, 2)}
            </pre>
          </div>
        </div>
      </div>
    </div>
  )
}

export default LogDetail
