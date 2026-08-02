import React from 'react'
import clsx from 'clsx'

type ColorVariant = 'threat' | 'warn' | 'ok' | 'signal' | 'gray'

interface StatCardProps {
  title: string
  value: string | number
  change?: number
  variant?: ColorVariant
}

const tickMap: Record<ColorVariant, string> = {
  threat: 'bg-threat',
  warn: 'bg-warn',
  ok: 'bg-ok',
  signal: 'bg-signal',
  gray: 'bg-hairline',
}

// A hairline-bordered instrument tile, not a rounded SaaS card. The top
// edge tick is a real state signal (elevated metrics shift color), not
// per-card decoration — most tiles stay neutral.
const StatCard: React.FC<StatCardProps> = ({ title, value, change, variant = 'gray' }) => {
  return (
    <div className="relative border border-hairline bg-panel p-4">
      <div className={clsx('absolute top-0 left-0 right-0 h-0.5', tickMap[variant])} />
      <p className="text-xs uppercase tracking-wider text-ink-dim">{title}</p>
      <p className="mt-1 text-2xl font-semibold text-ink tabular-nums">
        {typeof value === 'number' ? value.toLocaleString() : value}
      </p>
      {change !== undefined && (
        <div className="mt-2 flex items-center gap-1 text-xs">
          <span className={change >= 0 ? 'text-ok' : 'text-threat'}>
            {change >= 0 ? '▲' : '▼'} {Math.abs(change).toFixed(1)}%
          </span>
          <span className="text-ink-dim">vs last period</span>
        </div>
      )}
    </div>
  )
}

export default StatCard
