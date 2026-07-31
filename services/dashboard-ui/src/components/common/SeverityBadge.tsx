import React from 'react'
import { severityToClass } from '@/utils/color'
import { formatSeverity } from '@/utils/format'

interface SeverityBadgeProps {
  severity: string
}

const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity }) => {
  return (
    <span
      className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${severityToClass(severity)}`}
    >
      {formatSeverity(severity)}
    </span>
  )
}

export default SeverityBadge
