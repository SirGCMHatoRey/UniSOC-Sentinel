import React from 'react'
import { useUnacknowledgedCount } from '@/hooks/useAlerts'

const AlertBadge: React.FC = () => {
  const { data: count = 0 } = useUnacknowledgedCount()

  if (count === 0) return null

  return (
    <span className="inline-flex items-center justify-center px-1.5 py-0.5 rounded-full text-xs font-bold bg-siem-red text-white min-w-[1.25rem]">
      {count > 99 ? '99+' : count}
    </span>
  )
}

export default AlertBadge
