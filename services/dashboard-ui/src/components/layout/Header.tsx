import React, { useEffect, useState } from 'react'
import { useAuth } from '@/hooks/useAuth'
import AlertBadge from '@/components/alerts/AlertBadge'

const Header: React.FC = () => {
  const { user, logout } = useAuth()
  const [clock, setClock] = useState(() => new Date())

  useEffect(() => {
    const id = window.setInterval(() => setClock(new Date()), 1000)
    return () => window.clearInterval(id)
  }, [])

  const timeString = clock.toISOString().slice(11, 19)

  return (
    <header className="h-14 flex items-center justify-between px-6 bg-panel border-b border-hairline flex-shrink-0">
      <div className="flex items-center gap-4">
        <h1 className="font-display text-2xl font-bold tracking-wide text-ink leading-none">
          UNISOC SENTINEL
        </h1>
        <div className="hidden sm:flex items-center gap-2 text-xs text-ink-dim">
          <span className="w-1.5 h-1.5 bg-ok animate-pulse-dot" aria-hidden="true" />
          <span className="uppercase tracking-widest">Live</span>
          <span className="tabular-nums">{timeString}</span>
        </div>
      </div>

      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2">
          <span className="text-sm text-ink-dim uppercase tracking-wide">Alerts</span>
          <AlertBadge />
        </div>

        {user && (
          <div className="flex items-center gap-3">
            <div className="text-right">
              <p className="text-sm text-ink">{user.username}</p>
              <p className="text-xs text-ink-dim uppercase tracking-wide">{user.role}</p>
            </div>
            <button
              onClick={() => void logout()}
              className="px-3 py-1.5 text-sm bg-void border border-hairline hover:border-signal text-ink-dim hover:text-ink transition-colors"
            >
              Logout
            </button>
          </div>
        )}
      </div>
    </header>
  )
}

export default Header
