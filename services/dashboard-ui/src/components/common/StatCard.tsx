import React from 'react'
import clsx from 'clsx'

type ColorVariant = 'red' | 'orange' | 'yellow' | 'green' | 'blue' | 'gray'

interface StatCardProps {
  title: string
  value: string | number
  change?: number
  variant?: ColorVariant
  icon?: string
}

const variantMap: Record<ColorVariant, { border: string; text: string; bg: string }> = {
  red: { border: 'border-siem-red', text: 'text-siem-red', bg: 'bg-siem-red/10' },
  orange: { border: 'border-siem-orange', text: 'text-siem-orange', bg: 'bg-siem-orange/10' },
  yellow: { border: 'border-siem-yellow', text: 'text-siem-yellow', bg: 'bg-siem-yellow/10' },
  green: { border: 'border-siem-green', text: 'text-siem-green', bg: 'bg-siem-green/10' },
  blue: { border: 'border-siem-blue', text: 'text-siem-blue', bg: 'bg-siem-blue/10' },
  gray: { border: 'border-gray-600', text: 'text-gray-400', bg: 'bg-gray-600/10' },
}

const StatCard: React.FC<StatCardProps> = ({
  title,
  value,
  change,
  variant = 'blue',
  icon,
}) => {
  const styles = variantMap[variant]

  return (
    <div
      className={clsx(
        'rounded-lg border p-4 bg-siem-surface',
        styles.border
      )}
    >
      <div className="flex items-start justify-between">
        <div>
          <p className="text-sm text-gray-400">{title}</p>
          <p className={clsx('mt-1 text-2xl font-bold', styles.text)}>
            {typeof value === 'number' ? value.toLocaleString() : value}
          </p>
        </div>
        {icon && (
          <span className={clsx('text-2xl p-2 rounded-md', styles.bg)}>{icon}</span>
        )}
      </div>
      {change !== undefined && (
        <div className="mt-2 flex items-center gap-1 text-xs">
          <span className={change >= 0 ? 'text-siem-green' : 'text-siem-red'}>
            {change >= 0 ? '▲' : '▼'} {Math.abs(change).toFixed(1)}%
          </span>
          <span className="text-gray-500">vs last period</span>
        </div>
      )}
    </div>
  )
}

export default StatCard
