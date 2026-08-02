import React from 'react'
import { severityToLevel, severityToBarColor } from '@/utils/color'
import { formatSeverity } from '@/utils/format'

interface SeverityBadgeProps {
  severity: string
}

const TOTAL_BARS = 5

// Signature element: severity reads as a signal-strength meter (bars filling
// by tier) instead of a rounded pill — the vocabulary of signal-in-the-noise
// this tool's whole job is built on. Critical pulses; nothing else does.
const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity }) => {
  const level = severityToLevel(severity)
  const color = severityToBarColor(severity)
  const isCritical = severity.toLowerCase() === 'critical'

  return (
    <span
      className="inline-flex items-center gap-1.5"
      role="img"
      aria-label={`Severity: ${formatSeverity(severity)}`}
    >
      <span className="flex items-end gap-px h-3" aria-hidden="true">
        {Array.from({ length: TOTAL_BARS }, (_, i) => (
          <span
            key={i}
            className={
              i < level
                ? `w-1 ${color} ${isCritical ? 'animate-pulse-dot' : ''}`
                : 'w-1 bg-hairline'
            }
            style={{ height: `${((i + 1) / TOTAL_BARS) * 100}%` }}
          />
        ))}
      </span>
      <span className="text-xs font-medium uppercase tracking-wide text-ink-dim">
        {formatSeverity(severity)}
      </span>
    </span>
  )
}

export default SeverityBadge
