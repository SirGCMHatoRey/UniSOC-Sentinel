import React, { useState } from 'react'
import { NavLink } from 'react-router-dom'
import clsx from 'clsx'

interface NavItem {
  to: string
  label: string
  icon: string
}

const navItems: NavItem[] = [
  { to: '/dashboard', label: 'Dashboard', icon: '▦' },
  { to: '/logs', label: 'Logs', icon: '≡' },
  { to: '/alerts', label: 'Alerts', icon: '⚡' },
  { to: '/settings', label: 'Settings', icon: '⚙' },
]

const Sidebar: React.FC = () => {
  const [collapsed, setCollapsed] = useState(false)

  return (
    <aside
      className={clsx(
        'flex flex-col bg-panel border-r border-hairline transition-all duration-200',
        collapsed ? 'w-14' : 'w-56'
      )}
    >
      <div className="flex items-center justify-between px-3 py-4 border-b border-hairline">
        {!collapsed && (
          <span className="text-xs font-semibold text-ink-dim uppercase tracking-widest">
            UniSOC
          </span>
        )}
        <button
          onClick={() => setCollapsed(!collapsed)}
          className="text-ink-dim hover:text-ink p-1"
          aria-label="Toggle sidebar"
        >
          {collapsed ? '→' : '←'}
        </button>
      </div>

      <nav className="flex-1 py-3 space-y-1 px-2">
        {navItems.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            className={({ isActive }) =>
              clsx(
                'flex items-center gap-3 px-2 py-2 text-sm transition-colors border-l-2',
                isActive
                  ? 'border-signal bg-void text-ink'
                  : 'border-transparent text-ink-dim hover:border-hairline hover:text-ink'
              )
            }
          >
            <span className="text-lg leading-none flex-shrink-0">{item.icon}</span>
            {!collapsed && <span className="uppercase tracking-wide text-xs">{item.label}</span>}
          </NavLink>
        ))}
      </nav>

      <div className="p-3 border-t border-hairline">
        <div className={clsx('flex items-center gap-2', collapsed && 'justify-center')}>
          <div className="w-1.5 h-1.5 bg-ok animate-pulse-dot flex-shrink-0" />
          {!collapsed && (
            <span className="text-xs text-ink-dim uppercase tracking-wide">System Online</span>
          )}
        </div>
      </div>
    </aside>
  )
}

export default Sidebar
