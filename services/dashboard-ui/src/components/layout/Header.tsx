import React from 'react'
import { useAuth } from '@/hooks/useAuth'
import AlertBadge from '@/components/alerts/AlertBadge'

const Header: React.FC = () => {
  const { user, logout } = useAuth()

  return (
    <header className="h-14 flex items-center justify-between px-6 bg-siem-surface border-b border-siem-border flex-shrink-0">
      <div className="flex items-center gap-3">
        <span className="text-siem-accent text-xl">◈</span>
        <h1 className="text-lg font-semibold text-white">UniSOC Sentinel</h1>
      </div>

      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2">
          <span className="text-sm text-gray-400">Alerts</span>
          <AlertBadge />
        </div>

        {user && (
          <div className="flex items-center gap-3">
            <div className="text-right">
              <p className="text-sm text-white">{user.username}</p>
              <p className="text-xs text-gray-500 capitalize">{user.role}</p>
            </div>
            <button
              onClick={() => void logout()}
              className="px-3 py-1.5 text-sm bg-siem-border hover:bg-gray-600 text-gray-300 rounded-md transition-colors"
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
